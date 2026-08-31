const { $, $$ } = Uigg

const enc = (s) => new TextEncoder().encode(s)
const dec = (u8) => new TextDecoder().decode(u8)
const MAX_FILE = 50 * 1024 * 1024  // client-side UX guard; attachments stream to a blob, never into the room file
const POLL_PAGE = 40
const POLL_IDLE = 3000
const POLL_BUSY = 1200
const rndHex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('')

let key = null
let room = ''
let cid = ''
let displayName = ''
let since = 0
let dead = false
let idle = 0
// Optimistic UI bookkeeping: we render our own messages locally before the round trip
// finishes, so the copy poll() echoes back must be recognised and skipped.
const seenMid = new Set()
function markSent(mid) {
    seenMid.add(mid)
    if (seenMid.size > 1000) {
        for (const m of Array.from(seenMid).slice(0, 500)) seenMid.delete(m)
    }
}
let warm = false
let loadingLi = null
const sfx = {
    _play(f) {
        try {
            const a = new Audio('styles/' + f)
            a.volume = 0.5
            a.play().catch(() => {})
        } catch {}
    },
    send() { this._play('send.mp3') },
    recv() { this._play('receive.mp3') },
    end() { this._play('end.mp3') },
}

const loginSection = document.querySelector('section.login')
const chatEl = document.querySelector('chat')
const gateForm = $('#gate')
const roomInput = $('#room')
const passInput = $('#pass')
const enterBtn = $('#enter')
const chatMsg = $('chat-message')
const chatTitle = $('chat-title h3')
const chatOnline = $('chat-title span')
const chatControl = $('chat-control aside')
const sendBtn = $('chat-control .ico-arrow-enter')
const fileInput = $('chat-tool .ico-folder-empty input')
const clearBtn = $('chat-title .ico-delete')
const exitBtn = $('chat-title .ico-close')
const userInput = $('#user')
const attachBox = $('chat-attachments')
const pendingFiles = []

function fatal(msg) {
    Uigg.alert(msg)
}
if (!window.crypto || !crypto.subtle) {
    fatal('WebCrypto is unavailable. Please access via https:// or localhost. Plain http on a local network IP is not supported.')
    throw new Error('no secure context')
}

function bytesToB64(u8) {
    let s = ''
    for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000))
    return btoa(s)
}
function b64ToBytes(b64) {
    const s = atob(b64)
    const out = new Uint8Array(s.length)
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i)
    return out
}
async function deriveKey(pass, roomName) {
    const km = await crypto.subtle.importKey('raw', enc(pass), 'PBKDF2', false, ['deriveBits'])
    const bits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: enc('ephchat|' + roomName), iterations: 200000, hash: 'SHA-256' },
        km, 256)
    return crypto.subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
}
async function seal(bytes) {
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes))
    const out = new Uint8Array(12 + ct.length)
    out.set(iv, 0)
    out.set(ct, 12)
    return out
}
async function unseal(packed) {
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: packed.subarray(0, 12) }, key, packed.subarray(12)))
}
async function api(body) {
    const ctrl = new AbortController()
    const timer = setTimeout(() => ctrl.abort(), 20000)
    let r
    try {
        r = await fetch('api.php', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(body),
            signal: ctrl.signal,
        })
    } catch (e) {
        clearTimeout(timer)
        if (e.name === 'AbortError') throw new Error('request timed out (20s) — 多半被防火墙/WAF 拦截，或服务端无响应')
        throw e
    }
    clearTimeout(timer)
    if (!r.ok) throw new Error('http ' + r.status)
    return r.json()
}
async function apiRaw(query, bytes) {
    // Raw-binary transport: metadata rides in the query string, ciphertext rides in the
    // body verbatim. No base64 inflation, and nothing ever lands in the room file.
    const ctrl = new AbortController()
    const timer = setTimeout(() => ctrl.abort(), 60000)
    let r
    try {
        r = await fetch('api.php?' + new URLSearchParams(query).toString(), {
            method: 'POST',
            headers: { 'content-type': 'application/octet-stream' },
            body: bytes || new Uint8Array(0),
            signal: ctrl.signal,
        })
    } catch (e) {
        clearTimeout(timer)
        if (e.name === 'AbortError') throw new Error('transfer timed out (60s)')
        throw e
    }
    clearTimeout(timer)
    if (!r.ok) throw new Error('http ' + r.status)
    return r
}
function nearBottom() {
    return chatMsg.scrollHeight - chatMsg.scrollTop - chatMsg.clientHeight < 80
}
function scroll() {
    if (!nearBottom()) return
    requestAnimationFrame(() => { chatMsg.scrollTop = chatMsg.scrollHeight })
}
function bubble(mine, who) {
    const li = document.createElement('li')
    if (mine) li.className = 'mine'
    const cite = document.createElement('cite')
    const b = document.createElement('b')
    b.textContent = who || 'anon'
    const span = document.createElement('span')
    span.textContent = new Date().toLocaleTimeString()
    cite.appendChild(b)
    cite.appendChild(span)
    const aside = document.createElement('aside')
    li.appendChild(cite)
    li.appendChild(aside)
    chatMsg.appendChild(li)
    scroll()
    return aside
}
function sys(text) {
    const li = document.createElement('li')
    li.className = 'system'
    const aside = document.createElement('aside')
    aside.textContent = text
    li.appendChild(aside)
    chatMsg.appendChild(li)
    scroll()
    return li
}
function abbrName(n) {
    const dot = n.lastIndexOf('.')
    const ext = dot > 0 ? n.slice(dot) : ''
    if (n.length <= 16) return n
    return n.slice(0, 10) + '…' + ext
}
async function renderFile(aside, packed) {
    const metaLen = new DataView(packed.buffer, packed.byteOffset, packed.byteLength).getUint32(0)
    const meta = JSON.parse(dec(packed.subarray(4, 4 + metaLen)))
    const blob = new Blob([packed.subarray(4 + metaLen)], { type: meta.type || 'application/octet-stream' })
    const url = URL.createObjectURL(blob)
    aside.textContent = ''
    const type = meta.type || ''
    if (type.startsWith('image/')) {
        const img = document.createElement('img')
        img.src = url
        img.alt = meta.name
        img.addEventListener('load', scroll)
        img.addEventListener('error', scroll)
        aside.appendChild(img)
    } else if (type.startsWith('audio/')) {
        const audio = document.createElement('audio')
        audio.src = url
        audio.controls = true
        audio.addEventListener('loadeddata', scroll)
        aside.appendChild(audio)
    } else if (type.startsWith('video/')) {
        const video = document.createElement('video')
        video.src = url
        video.controls = true
        video.addEventListener('loadeddata', scroll)
        aside.appendChild(video)
    } else {
        const a = document.createElement('a')
        a.className = 'file-btn'
        a.href = url
        a.download = meta.name
        const ic = document.createElement('i')
        ic.className = 'ico ico-file'
        const sp = document.createElement('span')
        sp.textContent = abbrName(meta.name)
        sp.title = meta.name
        a.appendChild(ic)
        a.appendChild(sp)
        aside.appendChild(a)
    }
    scroll()
}
async function deliver(msg) {
    let env
    try {
        env = JSON.parse(dec(await unseal(b64ToBytes(msg.p))))
    } catch {
        sys('One message could not be decrypted (password mismatch)')
        return
    }
    // Already shown locally — do not render the echo a second time.
    if (env.mid && seenMid.has(env.mid)) return
    if (env.k === 'text') {
        renderText(bubble(env.cid === cid, env.name), env.v)
        if (!warm && env.cid !== cid) sfx.recv()
        return
    }
    if (env.k === 'fmeta') {
        // The room message is only a reference; the ciphertext lives in a blob.
        const aside = bubble(env.cid === cid, env.name)
        aside.textContent = 'Downloading…'
        try {
            const r = await apiRaw({ a: 'fetch', room, fid: env.fid })
            await renderFile(aside, await unseal(new Uint8Array(await r.arrayBuffer())))
            if (!warm && env.cid !== cid) sfx.recv()
        } catch {
            aside.textContent = 'File download failed'
        }
    }
}
async function loop() {
    while (!dead) {
        try {
            const r = await api({ a: 'poll', room, since, cid, limit: POLL_PAGE })
            if (r.gone) { sys('Room closed (idle for too long). Please re-enter'); dead = true; sfx.end(); return }
            if (typeof r.online === 'number') {
                chatTitle.textContent = '#' + room
                chatOnline.textContent = r.online + ' online'
            }
            if (typeof r.seq === 'number' && r.seq < since) {
                chatMsg.innerHTML = ''
                since = 0
                sys('Chat history has been cleared')
            }
            const msgs = r.msgs || []
            idle = msgs.length ? 0 : idle + 1
            for (const m of msgs) {
                await deliver(m)
                since = Math.max(since, m.i)
            }
            // History is paginated: keep pulling without pause, but yield the main
            // thread between pages so a long backlog cannot freeze the UI.
            if (r.more) {
                await new Promise((res) => setTimeout(res, 0))
                continue
            }
            if (loadingLi) { loadingLi.remove(); loadingLi = null }
            warm = false
        } catch {
            // transient network error: keep calm and poll again
        }
        await new Promise((r) => setTimeout(r, idle > 6 ? POLL_IDLE : POLL_BUSY))
    }
}
async function post(env) {
    const payload = bytesToB64(await seal(enc(JSON.stringify(Object.assign({ cid, name: displayName }, env)))))
    const r = await api({ a: 'post', room, payload, cid })
    since = Math.max(since, r.i)
    return r
}
function serializeEditor() {
    const out = []
    chatControl.childNodes.forEach((node) => {
        if (node.nodeType === 3) out.push(node.textContent)
        else if (node.nodeName === 'BR') out.push('\n')
        else if (node.nodeName === 'DIV') out.push('\n' + node.textContent)
        else if (node.nodeName === 'S') {
            const m = (node.getAttribute('style') || '').match(/emot\/(\d+)\.svg/)
            if (m) out.push('[[E' + m[1] + ']]')
        }
    })
    return out.join('')
}
function renderText(aside, text) {
    aside.textContent = ''
    const lines = text.split('\n')
    lines.forEach((line, i) => {
        if (i > 0) aside.appendChild(document.createElement('br'))
        const segs = line.split(/(\[\[E\d+\]\])/)
        for (const seg of segs) {
            if (!seg) continue
            const m = seg.match(/^\[\[E(\d+)\]\]$/)
            if (m) {
                const s = document.createElement('s')
                s.style.backgroundImage = 'url(//ui.gg/lib/emot/' + m[1] + '.svg)'
                aside.appendChild(s)
            } else {
                aside.appendChild(document.createTextNode(seg))
            }
        }
    })
}
async function send() {
    if (dead) return
    const text = serializeEditor().trim()
    const files = pendingFiles.slice()
    if (!text && files.length === 0) return
    sfx.send()
    chatControl.textContent = ''
    pendingFiles.length = 0
    renderAttachments()
    if (text) {
        const mid = rndHex(crypto.getRandomValues(new Uint8Array(8)))
        markSent(mid)
        const aside = bubble(true, displayName)
        renderText(aside, text)
        try { await post({ k: 'text', v: text, mid }) } catch { aside.textContent = text + '(Send failed)' }
    }
    for (const f of files) await sendFile(f)
}
async function sendFile(f) {
    if (dead) return
    if (f.size > MAX_FILE) {
        const msg = 'File size exceeded ' + (MAX_FILE / 1048576) + 'MB, Not sent.'
        console.warn('[chat] file rejected: ' + (f.size / 1048576).toFixed(1) + 'MB > limit ' + (MAX_FILE / 1048576) + 'MB')
        sys(msg)
        return
    }
    const aside = bubble(true, displayName)
    const mid = rndHex(crypto.getRandomValues(new Uint8Array(8)))
    const fid = rndHex(crypto.getRandomValues(new Uint8Array(8)))
    markSent(mid)
    aside.textContent = 'Encrypting…'
    try {
        const meta = enc(JSON.stringify({ name: f.name, type: f.type, size: f.size }))
        const body = new Uint8Array(await f.arrayBuffer())
        const packed = new Uint8Array(4 + meta.length + body.length)
        new DataView(packed.buffer).setUint32(0, meta.length)
        packed.set(meta, 4)
        packed.set(body, 4 + meta.length)
        // Encrypt once, then stream the raw ciphertext bytes into a server-side blob.
        // No base64 inflation, and not a single byte lands in the room file.
        const blob = await seal(packed)
        const begin = await api({ a: 'fbegin', room, fid, cid })
        const chunk = (begin.chunk | 0) || 512 * 1024
        const total = Math.ceil(blob.length / chunk) || 1
        for (let i = 0; i < total; i++) {
            aside.textContent = 'Uploading ' + (i + 1) + '/' + total
            await apiRaw({ a: 'fpart', room, fid, seq: i }, blob.subarray(i * chunk, (i + 1) * chunk))
        }
        // Announce only after the bytes are stored, so receivers never pull a partial blob.
        await post({ k: 'fmeta', fid, size: blob.length, mid })
        await renderFile(aside, packed)
    } catch (e) {
        console.error('[chat] sendFile failed:', e)
        const m = e && e.message && e.message.match(/http (\d+)/)
        aside.textContent = 'Send failed' + (m ? ' (http ' + m[1] + ')' : '')
    }
}
function sessionDestroyed(title, body) {
    dead = true
    sfx.end()
    loginSection.removeAttribute('hide')
    chatEl.setAttribute('hide', '')
    chatMsg.innerHTML = ''
    seenMid.clear()
    Uigg.alert((title || '') + (body ? '\n' + body : ''))
}
function exitRoom() {
    dead = true
    sfx.end()
    loginSection.removeAttribute('hide')
    chatEl.setAttribute('hide', '')
    key = null
    room = ''
    cid = ''
    since = 0
    chatMsg.innerHTML = ''
    pendingFiles.length = 0
    renderAttachments()
    seenMid.clear()
    roomInput.value = ''
    passInput.value = ''
    enterBtn.disabled = false
    enterBtn.textContent = 'Enter'
    chatTitle.textContent = 'name'
}
gateForm.addEventListener('submit', async (e) => {
    e.preventDefault()
    room = roomInput.value.trim()
    const pass = passInput.value
    displayName = (userInput.value || '').trim()
    if (!room || !pass || !displayName) return
    enterBtn.disabled = true
    enterBtn.textContent = 'Derived key…'
    try {
        dead = false
        key = await deriveKey(pass, room)
        const storeKey = 'bubble:cid:' + room
        let stored = ''
        try { stored = localStorage.getItem(storeKey) || '' } catch { }
        cid = stored || rndHex(crypto.getRandomValues(new Uint8Array(6)))
        if (!stored) { try { localStorage.setItem(storeKey, cid) } catch { } }
        since = 0
        const hello = await api({ a: 'hello', room, cid })
        chatOnline.textContent = typeof hello.online === 'number' ? hello.online + ' online' : ''
    } catch (err) {
        enterBtn.disabled = false
        enterBtn.textContent = 'Enter'
        sys('Failed to connect to server：' + err.message)
        return
    }
    loginSection.setAttribute('hide', '')
    chatEl.removeAttribute('hide')
    enterBtn.textContent = 'Enter'
    chatTitle.textContent = '#' + room
    loadingLi = sys('Loading history…')
    warm = true
    loop()
})
sendBtn.addEventListener('click', () => send())
chatControl.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.ctrlKey) { e.preventDefault(); send() }
    if (e.key === 'Enter' && e.ctrlKey) { e.preventDefault(); document.execCommand('insertLineBreak') }
})
fileInput.addEventListener('change', () => {
    const f = fileInput.files[0]
    fileInput.value = ''
    if (!f) return
    if (f.size > MAX_FILE) {
        const msg = 'File size exceeded ' + (MAX_FILE / 1048576) + 'MB, Not sent.'
        console.warn('[chat] file rejected: ' + (f.size / 1048576).toFixed(1) + 'MB > limit ' + (MAX_FILE / 1048576) + 'MB')
        sys(msg)
        return
    }
    pendingFiles.push(f)
    renderAttachments()
})
clearBtn.addEventListener('click', async () => {
    if (!room) return
    if (!(await Uigg.confirm('Are you sure you want to clear the chat history?'))) return
    try {
        await api({ a: 'clear', room, cid })
        chatMsg.innerHTML = ''
        sys('Chat history cleared')
    } catch {
        sys('Clear failed')
    }
})
exitBtn.addEventListener('click', async () => {
    if (!room) return
    if (!(await Uigg.confirm('Are you sure you want to leave the room?'))) return
    exitRoom()
})

// ===== UI extras: emot panel / image lightbox / room list =====
$$('chat-cont,chat-tip').forEach(el => el.classList.add('anime-fade-in'))
const chatCont = $('chat-cont')
const chatNew = () => scroll()
chatNew()
const emotBtn = $('chat-tool .ico-emot-smile')
emotBtn?.addEventListener('click', () => {
    const next = emotBtn.nextElementSibling
    next && (next.style.display = next.style.display === 'block' ? 'none' : 'block')
})
const focusEnd = el => {
    if (!el) return
    const range = document.createRange()
    range.selectNodeContents(el)
    range.collapse(false)
    const sel = window.getSelection()
    sel.removeAllRanges()
    sel.addRange(range)
    el.focus()
}
function insertEmot(srcS) {
    const s = document.createElement('s')
    const st = srcS.getAttribute('style')
    if (st) s.setAttribute('style', st)
    const sel = window.getSelection()
    if (sel && sel.rangeCount && chatControl.contains(sel.anchorNode)) {
        const range = sel.getRangeAt(0)
        range.deleteContents()
        range.insertNode(s)
        range.setStartAfter(s)
        range.collapse(true)
        sel.removeAllRanges()
        sel.addRange(range)
    } else {
        chatControl.appendChild(s)
    }
}
function renderAttachments() {
    if (!attachBox) return
    attachBox.textContent = ''
    if (pendingFiles.length === 0) { attachBox.hidden = true; return }
    attachBox.hidden = false
    pendingFiles.forEach((f, i) => {
        const chip = document.createElement('span')
        chip.className = 'att'
        const ic = document.createElement('i'); ic.className = 'ico ico-file'
        const sp = document.createElement('span'); sp.textContent = abbrName(f.name); sp.title = f.name
        const x = document.createElement('a'); x.className = 'ico ico-close'
        x.addEventListener('click', () => { pendingFiles.splice(i, 1); renderAttachments() })
        chip.appendChild(ic); chip.appendChild(sp); chip.appendChild(x)
        attachBox.appendChild(chip)
    })
}

document.addEventListener('click', e => {
    const s = e.target.closest?.('s')
    if (s && s.closest('[uigg="emot"]')) {
        const tip = s.closest('chat-tip')
        tip && (tip.style.display = 'none')
        insertEmot(s)
        focusEnd(chatControl)
        return
    }
    if (e.target.matches?.('chat aside img')) {
        const imgSrc = e.target.getAttribute('src')
        const pop = document.createElement('pop')
        pop.className = 'anime-fade-in center'
        pop.innerHTML = `<img src="${imgSrc}">`
        $('chat')?.appendChild(pop)
    }
    if (e.target.closest('chat pop')) { e.target.closest('chat pop').remove() }
})
$$('chat-list li').forEach(li => {
    li.addEventListener('click', () => {
        chatCont && (chatCont.style.display = 'flex')
        chatNew()
    })
})

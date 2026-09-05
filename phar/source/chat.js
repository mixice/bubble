let $ , $$
// Wait for the UIGG framework (a separate ES module from the ui.gg CDN) to be ready
// before touching $ / $$. Otherwise a module load-order race throws "Uigg is not defined"
// and leaves the entire chat dead on first paint.
function whenUigg(cb) {
    if (window.Uigg && typeof window.Uigg.$ === 'function') { cb(); return }
    const t = setInterval(() => {
        if (window.Uigg && typeof window.Uigg.$ === 'function') { clearInterval(t); cb() }
    }, 20)
    // Don't hang forever if the CDN is unreachable — surface a clear error instead.
    setTimeout(() => {
        if (!window.Uigg) {
            try { Uigg.alert('UI framework failed to load (ui.gg CDN unreachable).') }
            catch { alert('UI framework failed to load (ui.gg CDN unreachable).') }
        }
    }, 5000)
}

const enc = (s) => new TextEncoder().encode(s)
const dec = (u8) => new TextDecoder().decode(u8)
const MAX_FILE = 48 * 1024 * 1024  // leave room for per-chunk AES-GCM framing and metadata
const MAX_TEXT = 96 * 1024
const MAX_VOICE_MS = 3 * 60 * 1000  // hard cap so a stuck mic can't record forever; tune freely
const FILE_MAGIC = new Uint8Array([0x42, 0x46, 0x31, 0x01])
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
            const a = new Audio(f)
            a.volume = 0.5
            a.play().catch(() => {})
        } catch {}
    },
    send() { this._play('send.mp3') },
    recv() { this._play('receive.mp3') },
    end() { this._play('end.mp3') },
    del() { this._play('delete.mp3') },
}

function init() {
    $ = window.Uigg.$
    $$ = window.Uigg.$$
const chatEl = document.querySelector('chat')
const logoEl = document.querySelector('.logo')
const copyBtn = $('chat-title .ico-copy')
const chatMsg = $('chat-message')
const chatTitle = $('chat-title h3')
const chatControl = $('chat-control aside')
const sendBtn = $('chat-control .ico-arrow-enter')
const fileInput = $('chat-tool .ico-folder-empty input')
const clearBtn = $('chat-title .ico-delete')
const exitBtn = $('chat-title .ico-arrow-out')
const attachBox = $('chat-attachments')
const pendingFiles = []
const objectUrls = new Set()
// The 24-char woven token (room + secret interleaved) currently in use.
let currentToken = ''

// ---- stable device identity (persisted in localStorage) ----
// System-assigned nickname: one uppercase letter + three digits, e.g. A123.
// Persisted locally so the same device keeps one handle across all rooms.
const CFG_KEY = 'bubble:config'
const NICK_LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
function genRandomNick() {
    const L = NICK_LETTERS[crypto.getRandomValues(new Uint8Array(1))[0] % 26]
    const num = String(crypto.getRandomValues(new Uint8Array(2))[0] % 1000).padStart(3, '0')
    return L + num
}
function loadConfig() {
    try { return JSON.parse(localStorage.getItem(CFG_KEY) || '{}') } catch { return {} }
}
function saveConfig(cfg) {
    try { localStorage.setItem(CFG_KEY, JSON.stringify(cfg)) } catch {}
}
function getDeviceNick() {
    const cfg = loadConfig()
    if (cfg.name) return cfg.name
    cfg.name = genRandomNick()
    saveConfig(cfg)
    return cfg.name
}
// ---- woven token: room(12) + secret(12) interleaved into 24 chars ----
// Layout: room[0:4] secret[0:4] room[4:8] secret[4:8] room[8:12] secret[8:12]
// The token lives ONLY in the URL fragment (#), never sent to the server, never
// logged. Sharing the link = sharing the key; that is by design, not a leak.
const TOKEN_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
function randStr(n) {
    const out = new Array(n)
    const buf = crypto.getRandomValues(new Uint8Array(n))
    for (let i = 0; i < n; i++) out[i] = TOKEN_CHARS[buf[i] % 62]
    return out.join('')
}
function makeToken() {
    const room = randStr(12)
    const secret = randStr(12)
    let t = ''
    for (let i = 0; i < 3; i++) t += room.slice(i * 4, i * 4 + 4) + secret.slice(i * 4, i * 4 + 4)
    return { room, secret, token: t }
}
function parseToken(tok) {
    if (!tok || tok.length !== 24) return null
    if (!/^[A-Za-z0-9]{24}$/.test(tok)) return null
    const room = tok.slice(0, 4) + tok.slice(8, 12) + tok.slice(16, 20)
    const secret = tok.slice(4, 8) + tok.slice(12, 16) + tok.slice(20, 24)
    return { room, secret }
}
function shareUrl(tok) {
    return location.origin + location.pathname + '#' + tok
}
// One-tap copy of the full invite link. Room + key both live in the # fragment,
// so the link is self-contained and the server never sees either.
if (copyBtn) copyBtn.addEventListener('click', async () => {
    if (!currentToken) return
    const url = shareUrl(currentToken)
    try {
        await navigator.clipboard.writeText(url)
        Uigg.alert('Invitation link copied')
    } catch {
        Uigg.alert('Copy failed: ' + url)
    }
})

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
    if (packed.byteLength < 28) throw new Error('invalid ciphertext')
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: packed.subarray(0, 12) }, key, packed.subarray(12)))
}
async function sealChunk(bytes) {
    return seal(bytes)
}
async function decryptFileResponse(response) {
    if (!response.body) return { packed: new Uint8Array(await response.arrayBuffer()) }
    const reader = response.body.getReader()
    let pending = new Uint8Array(0)
    let ended = false
    const append = (chunk) => {
        if (!chunk || chunk.length === 0) return
        const next = new Uint8Array(pending.length + chunk.length)
        next.set(pending)
        next.set(chunk, pending.length)
        pending = next
    }
    const fill = async (need) => {
        while (!ended && pending.length < need) {
            const part = await reader.read()
            if (part.done) ended = true
            else append(part.value)
        }
        return pending.length >= need
    }
    const take = async (count) => {
        if (!(await fill(count))) throw new Error('truncated file')
        const out = pending.subarray(0, count)
        pending = pending.subarray(count)
        return out
    }
    const head = await take(FILE_MAGIC.length)
    if (!head.every((v, i) => v === FILE_MAGIC[i])) {
        // Legacy attachment: the whole response is one AES-GCM record. Preserve
        // compatibility by buffering only this old format.
        const rest = []
        if (head.length) rest.push(head)
        if (pending.length) { rest.push(pending); pending = new Uint8Array(0) }
        while (!ended) {
            const part = await reader.read()
            if (part.done) { ended = true; break }
            rest.push(part.value)
        }
        const total = rest.reduce((n, b) => n + b.length, 0)
        const packed = new Uint8Array(total)
        let at = 0
        for (const b of rest) { packed.set(b, at); at += b.length }
        return { packed }
    }
    let meta = null
    const parts = []
    while (true) {
        if (!(await fill(4))) break
        const frameHead = await take(4)
        const frameLen = new DataView(frameHead.buffer, frameHead.byteOffset, 4).getUint32(0)
        if (frameLen < 28 || frameLen > 1024 * 1024) throw new Error('invalid file frame')
        const plain = await unseal(await take(frameLen))
        if (meta === null) {
            if (plain.length < 4) throw new Error('invalid file metadata')
            const metaLen = new DataView(plain.buffer, plain.byteOffset, plain.byteLength).getUint32(0)
            if (metaLen <= 0 || metaLen > plain.length - 4) throw new Error('invalid file metadata')
            meta = JSON.parse(dec(plain.subarray(4, 4 + metaLen)))
            parts.push(plain.subarray(4 + metaLen))
        } else {
            parts.push(plain)
        }
    }
    if (meta === null) throw new Error('empty file')
    return { meta, blob: new Blob(parts, { type: meta.type || 'application/octet-stream' }) }
}
async function api(body) {
    const ctrl = new AbortController()
    const timer = setTimeout(() => ctrl.abort(), 20000)
    let r
    try {
        r = await fetch(location.pathname, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(body),
            signal: ctrl.signal,
        })
    } catch (e) {
        clearTimeout(timer)
        if (e.name === 'AbortError') throw new Error('request timed out (20s) — possibly blocked by firewall/WAF or server unresponsive')
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
        r = await fetch(location.pathname + '?' + new URLSearchParams(query).toString(), {
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
    if (packed.byteLength < 4) throw new Error('invalid file metadata')
    const metaLen = new DataView(packed.buffer, packed.byteOffset, packed.byteLength).getUint32(0)
    if (metaLen <= 0 || metaLen > packed.byteLength - 4) throw new Error('invalid file metadata')
    const meta = JSON.parse(dec(packed.subarray(4, 4 + metaLen)))
    const blob = new Blob([packed.subarray(4 + metaLen)], { type: meta.type || 'application/octet-stream' })
    return renderBlob(aside, meta, blob)
}
function renderBlob(aside, meta, blob) {
    const url = URL.createObjectURL(blob)
    objectUrls.add(url)
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
        // Some codecs can't be decoded on this device (e.g. Safari receiving webm/opus
        // from a Chromium sender). Never leave a broken player — fall back to a download.
        audio.addEventListener('error', () => {
            const a = document.createElement('a')
            a.className = 'file-btn'
            a.href = url
            a.download = meta.name || 'voice'
            a.textContent = 'Download voice message'
            aside.textContent = ''
            aside.appendChild(a)
        })
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
function revokeObjectUrls() {
    for (const url of objectUrls) URL.revokeObjectURL(url)
    objectUrls.clear()
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
            const r = await apiRaw({ a: 'fetch', room, fid: env.fid, cid })
            const decoded = await decryptFileResponse(r)
            if (decoded.packed) await renderFile(aside, await unseal(decoded.packed))
            else await renderBlob(aside, decoded.meta, decoded.blob)
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
            if (r.gone) {
                sessionDestroyed('Room closed', 'This room is no longer available.')
                return
            }
            if (typeof r.online === 'number') {
                chatTitle.textContent = r.online + ' online'
            }
            if (typeof r.seq === 'number' && r.seq < since) {
                chatMsg.innerHTML = ''
                revokeObjectUrls()
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
    const r = await api({ a: 'post', room, payload, cid, mid: env.mid })
    since = Math.max(since, r.i)
    return r
}
function serializeEditor() {
    const out = []
    chatControl.childNodes.forEach((node) => {
        if (node.nodeType === 3) out.push(node.textContent)
        else if (node.nodeName === 'BR') out.push('\n')
        else if (node.nodeName === 'DIV') out.push('\n' + node.textContent)
        else if (node.nodeName === 'S' || (node.nodeName === 'IMG' && node.classList.contains('emot'))) {
            const attr = node.nodeName === 'S' ? (node.getAttribute('style') || '') : (node.getAttribute('src') || '')
            const m = attr.match(/emot\/(\d+)\.svg/)
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
                const img = document.createElement('img')
                img.className = 'emot'
                img.src = '//ui.gg/lib/emot/' + m[1] + '.svg'
                img.setAttribute('contenteditable', 'false')
                aside.appendChild(img)
            } else {
                aside.appendChild(document.createTextNode(seg))
            }
        }
    })
}
async function send() {
    if (dead) return
    const text = serializeEditor().trim()
    if (enc(text).length > MAX_TEXT) {
        sys('Message is too long (maximum ' + Math.round(MAX_TEXT / 1024) + 'KB)')
        return
    }
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
        try { await post({ k: 'text', v: text, mid }) } catch { sys('Delivery status unknown; the server may still have received the message') }
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
        const firstPrefix = new Uint8Array(4 + meta.length)
        new DataView(firstPrefix.buffer).setUint32(0, meta.length)
        firstPrefix.set(meta, 4)
        const probe = await api({ a: 'fbegin', room, cid, probe: '1', size: 0 })
        // Leave headroom for the frame length, magic prefix, PHP request parsing,
        // and any proxy-added request overhead.
        const plainChunk = Math.max(16 * 1024, Math.min(512 * 1024, (probe.chunk | 0) - 8192 - 36))
        const totalPlain = firstPrefix.length + f.size
        const chunks = Math.ceil(totalPlain / plainChunk) || 1
        const encryptedSize = FILE_MAGIC.length + Array.from({ length: chunks }, (_, i) => {
            const plainLen = Math.min(plainChunk, totalPlain - i * plainChunk)
            return 4 + 12 + plainLen + 16
        }).reduce((a, b) => a + b, 0)
        await api({ a: 'fbegin', room, fid, cid, size: encryptedSize })
        // Encrypt each plaintext chunk independently. Each raw upload frame is
        // [uint32 ciphertext length][12-byte IV + ciphertext + 16-byte tag].
        let plainOffset = 0
        for (let i = 0; i < chunks; i++) {
            const plainLen = Math.min(plainChunk, totalPlain - plainOffset)
            const plain = new Uint8Array(plainLen)
            let at = 0
            if (plainOffset < firstPrefix.length) {
                const n = Math.min(firstPrefix.length - plainOffset, plainLen)
                plain.set(firstPrefix.subarray(plainOffset, plainOffset + n), at)
                at += n
                plainOffset += n
            }
            if (at < plainLen) {
                const fileOffset = Math.max(0, plainOffset - firstPrefix.length)
                plain.set(new Uint8Array(await f.slice(fileOffset, fileOffset + plainLen - at).arrayBuffer()), at)
                plainOffset += plainLen - at
            }
            const encrypted = await sealChunk(plain)
            const frame = new Uint8Array(4 + encrypted.length)
            new DataView(frame.buffer).setUint32(0, encrypted.length)
            frame.set(encrypted, 4)
            aside.textContent = 'Uploading ' + (i + 1) + '/' + chunks
            const upload = i === 0 ? new Uint8Array(FILE_MAGIC.length + frame.length) : frame
            if (i === 0) { upload.set(FILE_MAGIC); upload.set(frame, FILE_MAGIC.length) }
            await apiRaw({ a: 'fpart', room, fid, cid, seq: i }, upload)
        }
        await api({ a: 'fcommit', room, fid, cid })
        // Announce only after the bytes are stored, so receivers never pull a partial blob.
        await post({ k: 'fmeta', fid, size: encryptedSize, mid })
        // Render locally from the original file without another encryption/decryption pass.
        await renderBlob(aside, { name: f.name, type: f.type }, f)
    } catch (e) {
        console.error('[chat] sendFile failed:', e)
        aside.textContent = 'Delivery status unknown'
    }
}
// ===== Voice recording: record -> encrypt -> send via the existing file pipeline =====
// The recorded blob is handed to sendFile() as a normal File, so encryption, chunked
// upload, download and playback all reuse the attachment plumbing. Zero new server
// actions. Playback on the receive side is the native <audio> player (renderBlob's
// audio branch). Cross-codec edge cases (e.g. Safari receiving webm/opus) are handled
// by a download fallback in renderBlob().
let rec = null          // active MediaRecorder
let recChunks = []      // encoded chunks collected during recording
let recStream = null    // getUserMedia stream, so we can release the mic on stop
let recTimer = null     // safety auto-stop
let recEl = null        // the mic button element, to toggle its class
function pickAudioMime() {
    // Prefer the smallest universally-playable codec per browser. Chromium/Firefox
    // record webm/opus; Safari only records mp4/AAC.
    const cands = ['audio/webm;codecs=opus', 'audio/webm', 'audio/mp4;codecs=aac', 'audio/mp4', 'audio/aac']
    if (typeof MediaRecorder === 'undefined') return ''
    for (const c of cands) if (MediaRecorder.isTypeSupported(c)) return c
    return ''
}
async function toggleRecord() {
    if (dead || !room) return
    // Second click: stop recording (the 'stop' event does the send).
    if (rec) { try { rec.stop() } catch {} return }
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        Uigg.alert('This device/browser does not support audio recording')
        return
    }
    const mime = pickAudioMime()
    if (!mime) { Uigg.alert('Audio recording is not supported in this browser'); return }
    let stream
    try {
        stream = await navigator.mediaDevices.getUserMedia({ audio: true })
    } catch {
        Uigg.alert('Microphone permission denied')
        return
    }
    recStream = stream
    recChunks = []
    let recorder
    try {
        recorder = new MediaRecorder(stream, { mimeType: mime })
    } catch (e) {
        stream.getTracks().forEach((t) => t.stop())
        Uigg.alert('Failed to start recorder: ' + e.message)
        recStream = null
        return
    }
    rec = recorder
    recEl = document.querySelector('.ico-mic')
    recEl && recEl.classList.add('record')
    recorder.addEventListener('dataavailable', (e) => { if (e.data && e.data.size) recChunks.push(e.data) })
    recorder.addEventListener('stop', onRecStop)
    recorder.start()
    // Safety net: auto-stop at the hard cap so a forgotten tab can't record forever.
    recTimer = setTimeout(() => { try { rec && rec.stop() } catch {} }, MAX_VOICE_MS)
}
async function onRecStop() {
    clearTimeout(recTimer); recTimer = null
    if (recStream) { recStream.getTracks().forEach((t) => t.stop()); recStream = null }
    if (recEl) { recEl.classList.remove('record'); recEl = null }
    const mime = (rec && rec.mimeType) || 'audio/webm'
    const ext = (mime.includes('mp4') || mime.includes('aac')) ? 'mp4' : 'webm'
    const blob = new Blob(recChunks, { type: mime })
    recChunks = []
    rec = null
    if (!blob.size) return
    const name = 'voice-' + Date.now() + '.' + ext
    sfx.send()
    await sendFile(new File([blob], name, { type: mime }))
}
function sessionDestroyed(title, body) {
    dead = true
    sfx.end()
    if (logoEl) logoEl.removeAttribute('hide')
    chatEl.setAttribute('hide', '')
    chatMsg.innerHTML = ''
    revokeObjectUrls()
    seenMid.clear()
    currentToken = ''
    history.replaceState(null, '', location.pathname)
    Uigg.alert((title || '') + (body ? '\n' + body : ''))
}
async function exitRoom() {
    dead = true
    sfx.end()
    // Tell the server we're leaving so the online count drops immediately instead of
    // lingering for the full PEER_TIMEOUT heartbeat window (180s). Best-effort: if the
    // request fails the next sweep still reclaims the room.
    try { await api({ a: 'leave', room, cid }) } catch {}
    cid = ''
    if (logoEl) logoEl.removeAttribute('hide')
    chatEl.setAttribute('hide', '')
    key = null
    room = ''
    since = 0
    chatMsg.innerHTML = ''
    revokeObjectUrls()
    pendingFiles.length = 0
    renderAttachments()
    seenMid.clear()
    currentToken = ''
    chatTitle.textContent = ''
    // drop the #token so a refresh won't silently re-enter the room
    history.replaceState(null, '', location.pathname)
}
async function startChat() {
    if (logoEl) logoEl.setAttribute('hide', '')
    chatEl.removeAttribute('hide')
    loadingLi = sys('Loading history…')
    warm = true
    loop()
}
async function enterWithToken(tok) {
    const parsed = parseToken(tok)
    if (!parsed) { Uigg.alert('Invalid invite code: must be a 24-character alphanumeric token'); return false }
    currentToken = tok
    room = parsed.room
    displayName = getDeviceNick()
    try {
        dead = false
        key = await deriveKey(parsed.secret, room)
        const storeKey = 'bubble:cid:' + room
        let stored = ''
        try { stored = localStorage.getItem(storeKey) || '' } catch { }
        cid = stored || rndHex(crypto.getRandomValues(new Uint8Array(6)))
        if (!stored) { try { localStorage.setItem(storeKey, cid) } catch { } }
        since = 0
        const hello = await api({ a: 'hello', room, cid })
        chatTitle.textContent = typeof hello.online === 'number' ? hello.online + ' online' : ''
    } catch (err) {
        sys('Failed to connect to server: ' + err.message)
        return false
    }
    return true
}
async function createRoom() {
    const { token } = makeToken()
    // reflect the token in the address bar so the link can be copied directly
    history.replaceState(null, '', '#' + token)
    const ok = await enterWithToken(token)
    if (ok) {
        startChat()
        const url = shareUrl(token)
        try { await navigator.clipboard.writeText(url) } catch { }
        Uigg.alert('Invitation link copied')
    }
}
if (logoEl) logoEl.addEventListener('click', (e) => {
    e.preventDefault()
    createRoom()
})
// Enter (or switch to) a room from the #token in the URL. Runs both on first
// paint and when the user pastes a room link into an already-open tab. In the
// latter case the browser only changes the hash and does NOT reload, so we also
// listen for hashchange. createRoom/exitRoom call history.replaceState, which
// never fires hashchange, so this can't loop with those paths.
async function handleHashChange() {
    const tok = (location.hash || '').replace(/^#/, '').trim()
    if (!tok || !parseToken(tok)) {
        // Hash cleared while we're in a room -> leave it.
        if (!tok && room) exitRoom()
        return
    }
    if (tok === currentToken) return
    if (room) {
        // Switch rooms: drop the current session quietly. Don't touch the URL
        // (the pasted #token stays put) and don't play the end sound.
        dead = true
        try { await api({ a: 'leave', room, cid }) } catch {}
        cid = ''
        key = null
        room = ''
        since = 0
        chatMsg.innerHTML = ''
        revokeObjectUrls()
        pendingFiles.length = 0
        renderAttachments()
        seenMid.clear()
        currentToken = ''
        chatTitle.textContent = ''
    }
    const ok = await enterWithToken(tok)
    if (ok) startChat()
}
handleHashChange()
window.addEventListener('hashchange', handleHashChange)
sendBtn.addEventListener('click', () => send())
// Voice memo: tap to record (button turns red + spins), tap again to stop & send.
const micBtn = document.querySelector('.ico-mic')
if (micBtn) micBtn.addEventListener('click', () => toggleRecord())
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
// Paste a screenshot (or any image) from the clipboard as an encrypted attachment.
// contenteditable would otherwise inline the image as base64 and serializeEditor()
// silently drops it — so we intercept the paste, pull the image File out, and route
// it through the same sendFile() pipeline as a picked file.
chatControl.addEventListener('paste', (e) => {
    if (!room) return
    const cd = e.clipboardData || window.clipboardData
    if (!cd || !cd.items) return
    let added = false
    for (const it of cd.items) {
        if (it.kind === 'file' && it.type && it.type.startsWith('image/')) {
            const f = it.getAsFile()
            if (!f) continue
            if (f.size > MAX_FILE) {
                sys('File size exceeded ' + (MAX_FILE / 1048576) + 'MB, Not sent.')
                continue
            }
            const name = f.name || ('screenshot-' + Date.now() + '.png')
            pendingFiles.push(new File([f], name, { type: f.type || 'image/png' }))
            added = true
        }
    }
    if (added) {
        e.preventDefault()
        renderAttachments()
    }
})
clearBtn.addEventListener('click', async () => {
    if (!room) return
    if (!(await Uigg.confirm('Are you sure you want to clear the chat history?'))) return
    try {
        await api({ a: 'clear', room, cid })
        chatMsg.innerHTML = ''
        revokeObjectUrls()
        sfx.del()
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
const burnBtn = document.querySelector('.ico-close')
if (burnBtn) burnBtn.addEventListener('click', async () => {
    if (!room) return
    if (!(await Uigg.confirm('Are you sure you want to destroy the entire room? All messages and files will be permanently deleted, and others will be disconnected immediately.'))) return
    try {
        await api({ a: 'burn', room, cid })
        sessionDestroyed('Room destroyed. All data has been permanently cleared.')
    } catch {
        Uigg.alert('Destruction failed')
    }
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
let savedRange = null
const saveCaret = () => {
    const sel = window.getSelection()
    if (sel && sel.rangeCount > 0) {
        const r = sel.getRangeAt(0)
        if (chatControl && chatControl.contains(r.commonAncestorContainer)) savedRange = r.cloneRange()
    }
}
chatControl.addEventListener('keyup', saveCaret)
chatControl.addEventListener('mouseup', saveCaret)
chatControl.addEventListener('input', saveCaret)
function insertEmot(srcImg) {
    const img = document.createElement('img')
    img.className = 'emot'
    const src = srcImg.getAttribute('src')
    if (src) img.src = src
    img.setAttribute('contenteditable', 'false') // Firefox: keep caret outside the empty inline tag
    if (savedRange && chatControl.contains(savedRange.commonAncestorContainer)) {
        savedRange.collapse(true)
        savedRange.insertNode(img)
        savedRange.setStartAfter(img)
        savedRange.collapse(true)
        const sel = window.getSelection()
        sel.removeAllRanges()
        sel.addRange(savedRange)
        savedRange = savedRange.cloneRange()
    } else {
        chatControl.appendChild(img)
    }
}
let draggedEmot = null
chatControl.addEventListener('dragstart', e => {
    const img = e.target.closest?.('img')
    if (img && chatControl.contains(img)) {
        draggedEmot = img
        e.dataTransfer.effectAllowed = 'move'
        e.dataTransfer.setData('text/plain', '')
    }
})
chatControl.addEventListener('dragover', e => {
    if (draggedEmot) {
        e.preventDefault()
        e.dataTransfer.dropEffect = 'move'
    }
})
chatControl.addEventListener('drop', e => {
    if (!draggedEmot) return
    e.preventDefault()
    const dropped = draggedEmot
    draggedEmot = null
    let range = null
    if (document.caretRangeFromPoint) {
        range = document.caretRangeFromPoint(e.clientX, e.clientY)
    } else if (document.caretPositionFromPoint) {
        const p = document.caretPositionFromPoint(e.clientX, e.clientY)
        if (p) { range = document.createRange(); range.setStart(p.offsetNode, p.offset); range.collapse(true) }
    }
    if (range) {
        range.insertNode(dropped)
        range.setStartAfter(dropped)
        range.collapse(true)
        const sel = window.getSelection()
        sel.removeAllRanges()
        sel.addRange(range)
        savedRange = range.cloneRange()
    } else {
        chatControl.appendChild(dropped)
    }
    chatControl.focus()
})
chatControl.addEventListener('dragend', () => { draggedEmot = null })
chatControl.addEventListener('click', e => {
    const img = e.target.closest?.('img')
    if (!img) return
    const sel = window.getSelection()
    if (!sel || !sel.rangeCount || sel.getRangeAt(0).collapsed) return
    const rect = img.getBoundingClientRect()
    const after = (e.clientX - rect.left) > rect.width / 2
    const range = document.createRange()
    after ? range.setStartAfter(img) : range.setStartBefore(img)
    range.collapse(true)
    sel.removeAllRanges()
    sel.addRange(range)
    savedRange = range.cloneRange()
})
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
    const s = e.target.closest?.('img.emot')
    if (s && s.closest('[uigg="emot"]')) {
        const tip = s.closest('chat-tip')
        tip && (tip.style.display = 'none')
        insertEmot(s)
        chatControl.focus()
        return
    }
    if (e.target.matches?.('chat aside img:not(.emot)')) {
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

// Best-effort "I'm leaving" ping when the tab is closed or navigated away. A plain
// fetch inside exitRoom() is killed by the browser during unload, so the server never
// learns we left and the room + json.lock linger for the full 180s heartbeat window —
// or forever, if nobody else ever hits the server. sendBeacon survives unload; a
// keepalive fetch is the fallback. This is what keeps json.lock from piling up after use.
function beaconLeave() {
    if (!room || !cid || dead) return
    const body = JSON.stringify({ a: 'leave', room, cid })
    const url = location.pathname
    if (navigator.sendBeacon && navigator.sendBeacon(url, new Blob([body], { type: 'application/json' }))) return
    try { fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body, keepalive: true }) } catch {}
}
window.addEventListener('pagehide', beaconLeave)
window.addEventListener('beforeunload', beaconLeave)

}

whenUigg(init)

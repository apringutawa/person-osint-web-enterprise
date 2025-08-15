import React, { useState } from 'react'

const API = import.meta.env.VITE_API_BASE || 'http://localhost:8000'

function useFetch() {
  const [loading, setLoading] = useState(false)
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)

  const postForm = async (path, formData) => {
    setLoading(true); setError(null); setData(null)
    try {
      const headers = {}
      const token = localStorage.getItem('osint_jwt') || localStorage.getItem('osint_token')
      if (token) headers['Authorization'] = 'Bearer ' + token
      const res = await fetch(`${API}${path}`, { method: 'POST', body: formData, headers })
      if(!res.ok){
        const text = await res.text()
        throw new Error(text || `HTTP ${res.status}`)
      }
      const json = await res.json()
      setData(json)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }
  return { loading, data, error, postForm }
}

const Section = ({ title, children, subtitle }) => (
  <div className="card">
    <h3>{title}</h3>
    {subtitle && <div className="muted">{subtitle}</div>}
    {children}
  </div>
)

function AuthBar(){
  const [user, setUser] = useState('analyst')
  const [pass, setPass] = useState('analyst123')
  const [token, setToken] = useState(localStorage.getItem('osint_jwt') || '')

  const login = async (e)=>{
    e.preventDefault()
    const fd = new FormData()
    fd.append('username', user)
    fd.append('password', pass)
    const res = await fetch(`${API}/auth/login`, { method:'POST', body: fd })
    if(!res.ok){ alert('Login gagal'); return }
    const json = await res.json()
    localStorage.setItem('osint_jwt', json.token)
    setToken(json.token)
    alert('Login berhasil. Token tersimpan.')
  }

  return (
    <div className="bar">
      <span className="muted">Login (JWT)</span>
      <input type="text" placeholder="username" value={user} onChange={e=>setUser(e.target.value)} />
      <input type="password" placeholder="password" value={pass} onChange={e=>setPass(e.target.value)} />
      <button onClick={login}>Login</button>
      <input type="text" placeholder="tempel token manual (opsional)" value={token} onChange={e=>setToken(e.target.value)} />
      <button onClick={()=>{ localStorage.setItem('osint_jwt', token); alert('Token disimpan.'); }}>Simpan Token</button>
      <button onClick={()=>{ localStorage.removeItem('osint_jwt'); setToken(''); alert('Token dihapus.'); }}>Logout</button>
    </div>
  )
}

export default function App(){
  const [caseId, setCaseId] = useState('case-001')
  return (
    <div className="wrap">
      <div className="title">🕵️ Person OSINT Web Enterprise</div>
      <div className="subtitle">Case ID, Report (HTML & PDF), PhoneInfoga, HIBP, Hunter, Clearbit. JWT + rate limit.</div>
      <AuthBar />
      <div className="bar">
        <span>Case ID</span>
        <input type="text" value={caseId} onChange={e=>setCaseId(e.target.value)} />
      </div>
      <div className="grid">
        <UsernameCard caseId={caseId} />
        <EmailCard caseId={caseId} />
        <PhoneCard caseId={caseId} />
        <ExifCard caseId={caseId} />
        <WaybackCard caseId={caseId} />
        <HibpCard caseId={caseId} />
        <HunterCard caseId={caseId} />
        <ClearbitCard caseId={caseId} />
        <ReportCard caseId={caseId} />
        <ReportPdfCard caseId={caseId} />
      </div>
      <div className="footer">
        Etik & legal: gunakan hanya data sumber terbuka; patuhi hukum & ToS; lakukan verifikasi silang. Enumeration ≠ identitas.
      </div>
    </div>
  )
}

function UsernameCard({ caseId }){
  const [username, setUsername] = useState('')
  const { loading, data, error, postForm } = useFetch()
  const submit = e => {
    e.preventDefault()
    const fd = new FormData()
    fd.append('username', username)
    fd.append('timeout', '10')
    fd.append('case_id', caseId)
    postForm('/username', fd)
  }
  return (
    <Section title="Enumerasi Username (Maigret)" subtitle="Cari jejak akun lintas platform">
      <form onSubmit={submit}>
        <label>Username</label>
        <input type="text" value={username} onChange={e=>setUsername(e.target.value)} placeholder="mis. johndoe" />
        <div className="row"><button className="primary" disabled={!username || loading}>{loading ? 'Memproses...' : 'Jalankan'}</button></div>
      </form>
      <Result data={data} error={error} />
    </Section>
  )
}

function EmailCard({ caseId }){
  const [email, setEmail] = useState('')
  const { loading, data, error, postForm } = useFetch()
  const submit = e => {
    e.preventDefault()
    const fd = new FormData()
    fd.append('email', email)
    fd.append('only_used', 'true')
    fd.append('case_id', caseId)
    postForm('/email', fd)
  }
  return (
    <Section title="Cek Email (Holehe)" subtitle="Deteksi layanan yang pernah memakai email target">
      <form onSubmit={submit}>
        <label>Email</label>
        <input type="email" value={email} onChange={e=>setEmail(e.target.value)} placeholder="nama@contoh.com" />
        <div className="row"><button className="primary" disabled={!email || loading}>{loading ? 'Memproses...' : 'Jalankan'}</button></div>
      </form>
      <Result data={data} error={error} />
    </Section>
  )
}

function PhoneCard({ caseId }){
  const [number, setNumber] = useState('')
  const { loading, data, error, postForm } = useFetch()
  const submit = e => {
    e.preventDefault()
    const fd = new FormData()
    fd.append('number', number)
    fd.append('case_id', caseId)
    postForm('/phone', fd)
  }
  return (
    <Section title="Nomor Telepon (PhoneInfoga)" subtitle="Scan nomor telepon (gunakan +62, dsb.)">
      <form onSubmit={submit}>
        <label>Nomor</label>
        <input type="text" value={number} onChange={e=>setNumber(e.target.value)} placeholder="+62xxxxxxxxxx" />
        <div className="row"><button className="primary" disabled={!number || loading}>{loading ? 'Memproses...' : 'Jalankan'}</button></div>
      </form>
      <Result data={data} error={error} />
    </Section>
  )
}

function ExifCard({ caseId }){
  const [file, setFile] = useState(null)
  const { loading, data, error, postForm } = useFetch()
  const submit = e => {
    e.preventDefault()
    if(!file) return
    const fd = new FormData()
    fd.append('file', file)
    fd.append('case_id', caseId)
    postForm('/exif', fd)
  }
  return (
    <Section title="Foto → EXIF (ExifTool)" subtitle="Ekstrak metadata dari foto">
      <form onSubmit={submit}>
        <label>Unggah foto</label>
        <input type="file" accept="image/*" onChange={e=>setFile(e.target.files?.[0])} />
        <div className="row"><button className="primary" disabled={!file || loading}>{loading ? 'Memproses...' : 'Jalankan'}</button></div>
      </form>
      <Result data={data} error={error} />
    </Section>
  )
}

function WaybackCard({ caseId }){
  const [url, setUrl] = useState('')
  const { loading, data, error, postForm } = useFetch()
  const submit = e => {
    e.preventDefault()
    const fd = new FormData()
    fd.append('url', url)
    fd.append('case_id', caseId)
    postForm('/wayback', fd)
  }
  return (
    <Section title="Arsip Halaman (Wayback)" subtitle="Lookup & Save Page Now">
      <form onSubmit={submit}>
        <label>URL</label>
        <input type="url" value={url} onChange={e=>setUrl(e.target.value)} placeholder="https://..." />
        <div className="row"><button className="primary" disabled={!url || loading}>{loading ? 'Memproses...' : 'Jalankan'}</button></div>
      </form>
      <Result data={data} error={error} />
    </Section>
  )
}

function HibpCard({ caseId }){
  const [email, setEmail] = useState('')
  const [truncate, setTrunc] = useState(false)
  const { loading, data, error, postForm } = useFetch()
  const submit = e => {
    e.preventDefault()
    const fd = new FormData()
    fd.append('email', email)
    fd.append('truncate', String(truncate))
    fd.append('case_id', caseId)
    postForm('/hibp', fd)
  }
  return (
    <Section title="HIBP (Breach by Email)" subtitle="Butuh HIBP_API_KEY di backend">
      <form onSubmit={submit}>
        <label>Email</label>
        <input type="email" value={email} onChange={e=>setEmail(e.target.value)} placeholder="nama@contoh.com" />
        <div className="row">
          <button className="primary" disabled={!email || loading}>{loading ? 'Memproses...' : 'Jalankan'}</button>
          <label className="muted"><input type="checkbox" checked={truncate} onChange={e=>setTrunc(e.target.checked)} /> Truncate</label>
        </div>
      </form>
      <Result data={data} error={error} />
    </Section>
  )
}

function HunterCard({ caseId }){
  const [email, setEmail] = useState('')
  const { loading, data, error, postForm } = useFetch()
  const submit = e => {
    e.preventDefault()
    const fd = new FormData()
    fd.append('email', email)
    fd.append('case_id', caseId)
    postForm('/hunter', fd)
  }
  return (
    <Section title="Hunter.io Verifier" subtitle="Butuh HUNTER_API_KEY di backend">
      <form onSubmit={submit}>
        <label>Email</label>
        <input type="email" value={email} onChange={e=>setEmail(e.target.value)} placeholder="nama@contoh.com" />
        <div className="row"><button className="primary" disabled={!email || loading}>{loading ? 'Memproses...' : 'Jalankan'}</button></div>
      </form>
      <Result data={data} error={error} />
    </Section>
  )
}

function ClearbitCard({ caseId }){
  const [email, setEmail] = useState('')
  const { loading, data, error, postForm } = useFetch()
  const submit = e => {
    e.preventDefault()
    const fd = new FormData()
    fd.append('email', email)
    fd.append('case_id', caseId)
    postForm('/clearbit', fd)
  }
  return (
    <Section title="Clearbit Enrichment" subtitle="Butuh CLEARBIT_API_KEY di backend">
      <form onSubmit={submit}>
        <label>Email</label>
        <input type="email" value={email} onChange={e=>setEmail(e.target.value)} placeholder="nama@contoh.com" />
        <div className="row"><button className="primary" disabled={!email || loading}>{loading ? 'Memproses...' : 'Jalankan'}</button></div>
      </form>
      <Result data={data} error={error} />
    </Section>
  )
}

function ReportCard({ caseId }){
  const { loading, data, error, postForm } = useFetch()
  const submit = e => {
    e.preventDefault()
    const fd = new FormData()
    fd.append('case_id', caseId)
    postForm('/report', fd)
  }
  return (
    <Section title="Report HTML" subtitle="Gabungkan semua temuan pada Case ID menjadi satu halaman HTML">
      <form onSubmit={submit}>
        <div className="row"><button className="primary" disabled={loading}>{loading ? 'Menyusun...' : 'Buat Report'}</button></div>
      </form>
      <Result data={data} error={error} />
    </Section>
  )
}

function ReportPdfCard({ caseId }){
  const { loading, data, error, postForm } = useFetch()
  const submit = e => {
    e.preventDefault()
    const fd = new FormData()
    fd.append('case_id', caseId)
    postForm('/report_pdf', fd)
  }
  return (
    <Section title="Report PDF" subtitle="Konversi report HTML menjadi PDF (headless Chromium)">
      <form onSubmit={submit}>
        <div className="row"><button className="primary" disabled={loading}>{loading ? 'Mencetak...' : 'Buat PDF'}</button></div>
      </form>
      <Result data={data} error={error} />
    </Section>
  )
}

function Result({ data, error }){
  if(error) return <div className="out fail">Error: {error}</div>
  if(!data) return null
  const API = import.meta.env.VITE_API_BASE || 'http://localhost:8000'
  return (
    <div style={{marginTop:12}}>
      <div className="kpi"><span className="pill">{data.ok ? 'OK' : 'Gagal'}</span></div>
      <div className="links" style={{margin:'10px 0'}}>
        {data.html && <a href={`${API}${data.html}`} target="_blank">Unduh HTML</a>}
        {data.json && <a href={`${API}${data.json}`} target="_blank">Unduh JSON</a>}
        {data.txt && <a href={`${API}${data.txt}`} target="_blank">Unduh TXT</a>}
        {data.upload && <a href={`${API}${data.upload}`} target="_blank">File Terunggah</a>}
        {data.pdf && <a href={`${API}${data.pdf}`} target="_blank">Unduh PDF</a>}
      </div>
      <div className="out"><code>{JSON.stringify(data, null, 2)}</code></div>
    </div>
  )
}

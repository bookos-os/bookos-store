const invoke = (cmd, args) => window.__TAURI__.core.invoke(cmd, args);
const tauriWin = () => window.__TAURI__.window.getCurrentWindow();
const $ = (s, r=document) => r.querySelector(s);

let allApps = [];
let carga = 'cargando';       // cargando | lista | error
let motivoCarga = '';         // lo que contestó el backend cuando carga === 'error'
let refrescando = false;
let ruta = 'discover';        // discover | installed | updates | settings | cat:<categoría>
let busqueda = '';
let pmInfo = { pm: 'pacman', exts: ['.pkg.tar.zst'] };
let currentApp = null;        // app object when in detail view, else null
let lightboxIdx = -1;         // open screenshot index, -1 closed
let scrollLista = 0;          // para volver de una ficha al punto donde se estaba
let op = null;                // { text, pct (null = indeterminada), cancellable }
let fallo = null;             // { pkg, stage, file, msg, retry } — último error de operación

// ───── i18n ─────
// El idioma y el tema se eligen en Ajustes de BookOS, no por ventana.
const i18n = (k, v) => window.BookosI18n.t(k, v);
const lang = () => window.BookosI18n.getLang();

// Pick localized string from app: try `<field>_<lang>`, fall back to base field.
function pickL(obj, field) {
  const l = lang();
  if (l !== 'es') {
    const v = obj[field + '_' + l];
    if (v) return v;
  }
  return obj[field] || '';
}
const getLabel = a => pickL(a, 'label') || a.pkg;
const getDesc  = a => pickL(a, 'description');
const getNotes = r => pickL(r || {}, 'notes');
const verCorta = v => String(v).split('-')[0];

function assetCompat(asset, pm) {
  if (!asset || !asset.name) return false;
  const k = (asset.kind || '').toLowerCase();
  if (k) {
    if (pm === 'pacman' && k === 'pacman') return true;
    if (pm === 'dnf'    && (k === 'dnf' || k === 'rpm')) return true;
    if (pm === 'apt'    && (k === 'apt' || k === 'deb')) return true;
    if (k === 'appimage') return true;
    return false;
  }
  const n = asset.name.toLowerCase();
  if (pm === 'pacman') return n.endsWith('.pkg.tar.zst');
  if (pm === 'dnf')    return n.endsWith('.rpm');
  if (pm === 'apt')    return n.endsWith('.deb');
  return false;
}
const assetDe = a => (a.release_assets || []).find(x => assetCompat(x, pmInfo.pm || 'pacman'));

const iconCache = new Map();
window.addEventListener('contextmenu', e => e.preventDefault());

async function getIcon(name, iconUrl) {
  if (iconCache.has(name)) return;
  let data = await invoke('get_icon', { name }).catch(() => '');
  if (!data && iconUrl) {
    // Sin icono no se rompe nada: la app sale con su inicial.
    data = await fetch(iconUrl, { cache: 'no-store' })
      .then(r => r.ok ? r.blob() : null)
      .then(blob => blob && new Promise(res => { const fr = new FileReader(); fr.onload = () => res(fr.result); fr.readAsDataURL(blob); }))
      .catch(() => '');
  }
  iconCache.set(name, data || '');
}

function iconHtml(app, cls='') {
  const data = iconCache.get(app.icon || app.pkg);
  return `<div class="app-ico ${cls}">${data
    ? `<img src="${data}" alt="" draggable="false">`
    : `<span>${escapeHtml((getLabel(app) || '?')[0].toUpperCase())}</span>`}</div>`;
}

// ───── ICONOS ─────
// Sistema B: Heroicons 2.1.5 outline (BookOS-HIG/heroicons/24/outline), trazo 2.
const TRAZOS = {
  download: 'M3 16.5v2.25A2.25 2.25 0 0 0 5.25 21h13.5A2.25 2.25 0 0 0 21 18.75V16.5M16.5 12 12 16.5m0 0L7.5 12m4.5 4.5V3',
  refresh:  'M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0 3.181 3.183a8.25 8.25 0 0 0 13.803-3.7M4.031 9.865a8.25 8.25 0 0 1 13.803-3.7l3.181 3.182m0-4.991v4.99',
  play:     'M5.25 5.653c0-.856.917-1.398 1.667-.986l11.54 6.347a1.125 1.125 0 0 1 0 1.972l-11.54 6.347a1.125 1.125 0 0 1-1.667-.986V5.653Z',
  check:    'm4.5 12.75 6 6 9-13.5',
  left:     'M15.75 19.5 8.25 12l7.5-7.5',
  right:    'm8.25 4.5 7.5 7.5-7.5 7.5',
  close:    'M6 18 18 6M6 6l12 12',
  warn:     'M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z',
  external: 'M13.5 6H5.25A2.25 2.25 0 0 0 3 8.25v10.5A2.25 2.25 0 0 0 5.25 21h10.5A2.25 2.25 0 0 0 18 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25',
  search:   'm21 21-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z',
  grid:     'M3.75 6A2.25 2.25 0 0 1 6 3.75h2.25A2.25 2.25 0 0 1 10.5 6v2.25a2.25 2.25 0 0 1-2.25 2.25H6a2.25 2.25 0 0 1-2.25-2.25V6ZM3.75 15.75A2.25 2.25 0 0 1 6 13.5h2.25a2.25 2.25 0 0 1 2.25 2.25V18a2.25 2.25 0 0 1-2.25 2.25H6A2.25 2.25 0 0 1 3.75 18v-2.25ZM13.5 6a2.25 2.25 0 0 1 2.25-2.25H18A2.25 2.25 0 0 1 20.25 6v2.25A2.25 2.25 0 0 1 18 10.5h-2.25a2.25 2.25 0 0 1-2.25-2.25V6ZM13.5 15.75a2.25 2.25 0 0 1 2.25-2.25H18a2.25 2.25 0 0 1 2.25 2.25V18A2.25 2.25 0 0 1 18 20.25h-2.25A2.25 2.25 0 0 1 13.5 18v-2.25Z',
};
const ico = (name, size=16, sw=2) =>
  `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="${sw}" stroke-linecap="round" stroke-linejoin="round"><path d="${TRAZOS[name]}"/></svg>`;

// Sistema A: glifo relleno (Heroicons solid) sobre el color de la sección.
const RELLENOS = {
  star:    'M10.788 3.21c.448-1.077 1.976-1.077 2.424 0l2.082 5.006 5.404.434c1.164.093 1.636 1.545.749 2.305l-4.117 3.527 1.257 5.273c.271 1.136-.964 2.033-1.96 1.425L12 18.354 7.373 21.18c-.996.608-2.231-.29-1.96-1.425l1.257-5.273-4.117-3.527c-.887-.76-.415-2.212.749-2.305l5.404-.434 2.082-5.005Z',
  grid:    'M3 6a3 3 0 0 1 3-3h2.25a3 3 0 0 1 3 3v2.25a3 3 0 0 1-3 3H6a3 3 0 0 1-3-3V6Zm9.75 0a3 3 0 0 1 3-3H18a3 3 0 0 1 3 3v2.25a3 3 0 0 1-3 3h-2.25a3 3 0 0 1-3-3V6ZM3 15.75a3 3 0 0 1 3-3h2.25a3 3 0 0 1 3 3V18a3 3 0 0 1-3 3H6a3 3 0 0 1-3-3v-2.25Zm9.75 0a3 3 0 0 1 3-3H18a3 3 0 0 1 3 3V18a3 3 0 0 1-3 3h-2.25a3 3 0 0 1-3-3v-2.25Z',
  down:    'M12 2.25c-5.385 0-9.75 4.365-9.75 9.75s4.365 9.75 9.75 9.75 9.75-4.365 9.75-9.75S17.385 2.25 12 2.25Zm-.53 14.03a.75.75 0 0 0 1.06 0l3-3a.75.75 0 1 0-1.06-1.06l-1.72 1.72V8.25a.75.75 0 0 0-1.5 0v5.69l-1.72-1.72a.75.75 0 0 0-1.06 1.06l3 3Z',
  cog:     'M11.078 2.25c-.917 0-1.699.663-1.85 1.567L9.05 4.889c-.02.12-.115.26-.297.348a7.493 7.493 0 0 0-.986.57c-.166.115-.334.126-.45.083L6.3 5.508a1.875 1.875 0 0 0-2.282.819l-.922 1.597a1.875 1.875 0 0 0 .432 2.385l.84.692c.095.078.17.229.154.43a7.598 7.598 0 0 0 0 1.139c.015.2-.059.352-.153.43l-.841.692a1.875 1.875 0 0 0-.432 2.385l.922 1.597a1.875 1.875 0 0 0 2.282.818l1.019-.382c.115-.043.283-.031.45.082.312.214.641.405.985.57.182.088.277.228.297.35l.178 1.071c.151.904.933 1.567 1.85 1.567h1.844c.916 0 1.699-.663 1.85-1.567l.178-1.072c.02-.12.114-.26.297-.349.344-.165.673-.356.985-.57.167-.114.335-.125.45-.082l1.02.382a1.875 1.875 0 0 0 2.28-.819l.923-1.597a1.875 1.875 0 0 0-.432-2.385l-.84-.692c-.095-.078-.17-.229-.154-.43a7.614 7.614 0 0 0 0-1.139c-.016-.2.059-.352.153-.43l.84-.692c.708-.582.891-1.59.433-2.385l-.922-1.597a1.875 1.875 0 0 0-2.282-.818l-1.02.382c-.114.043-.282.031-.449-.083a7.49 7.49 0 0 0-.985-.57c-.183-.087-.277-.227-.297-.348l-.179-1.072a1.875 1.875 0 0 0-1.85-1.567h-1.843ZM12 15.75a3.75 3.75 0 1 0 0-7.5 3.75 3.75 0 0 0 0 7.5Z',
  refresh: 'M4.755 10.059a7.5 7.5 0 0 1 12.548-3.364l1.903 1.903h-3.183a.75.75 0 1 0 0 1.5h4.992a.75.75 0 0 0 .75-.75V4.356a.75.75 0 0 0-1.5 0v3.18l-1.9-1.9A9 9 0 0 0 3.306 9.67a.75.75 0 1 0 1.45.388Zm15.408 3.352a.75.75 0 0 0-.919.53 7.5 7.5 0 0 1-12.548 3.364l-1.902-1.903h3.183a.75.75 0 0 0 0-1.5H2.984a.75.75 0 0 0-.75.75v4.992a.75.75 0 0 0 1.5 0v-3.18l1.9 1.9a9 9 0 0 0 15.059-4.035.75.75 0 0 0-.53-.918Z',
};
const navIco = (name, color) =>
  `<span class="nav-ico" style="background:var(--${color})"><svg viewBox="0 0 24 24"><path fill-rule="evenodd" clip-rule="evenodd" d="${RELLENOS[name]}"/></svg></span>`;
// Las categorías llegan del catálogo, no hay lista cerrada: el color va por
// posición, que es lo que garantiza que dos vecinas no compartan el mismo.
const COLORES_CAT = ['purple', 'indigo', 'pink', 'yellow', 'red'];

// ───── TEMA ─────
async function applyTheme() {
  const sys = await invoke('detect_system_theme').catch(() => 'auto');
  const root = document.documentElement;
  root.classList.toggle('dark-mode', sys === 'dark');
  root.classList.toggle('light-mode', sys === 'light');
}

// ───── TOAST ─────
let toastTimer;
function toast(msg){const t=$('#toast');t.textContent=msg;t.classList.add('show');clearTimeout(toastTimer);toastTimer=setTimeout(()=>t.classList.remove('show'),3000);}

const errMsg = e => typeof e === 'string' ? e : (e.message || JSON.stringify(e));

// ───── LOAD APPS ─────
async function loadApps() {
  pmInfo = await invoke('pm_info').catch(() => pmInfo);
  let apps;
  try {
    apps = await invoke('list_apps');
  } catch (e) {
    // Con apps ya en pantalla no se tira la vista por un refresco fallido.
    if (allApps.length) { toast(i18n('errCatalog', { m: errMsg(e).slice(0, 140) })); return; }
    carga = 'error';
    motivoCarga = errMsg(e);
    render();
    return;
  }
  for (const a of apps) {
    a.release_assets = a.assets || [];
    a.manual = a.installed === 'manual';  // binary present, not tracked by pm
    a.has_update = !!(a.installed && a.available && !a.manual) && (cmpVer(a.available, verCorta(a.installed)) > 0 || a.changed);
  }
  await Promise.all(apps.map(a => getIcon(a.icon || a.pkg, a.icon_url)));
  if (currentApp) {
    // El listado no trae el historial: se conserva el que ya se había pedido.
    const nueva = apps.find(x => x.pkg === currentApp.pkg) || null;
    if (nueva) nueva.releases = currentApp.releases;
    currentApp = nueva;
  }
  allApps = apps;
  carga = 'lista';
  if (ruta.startsWith('cat:') && !apps.some(a => 'cat:' + a.category === ruta)) ruta = 'discover';
  render();
}

async function refrescar() {
  if (refrescando) return;
  refrescando = true;
  $('#page [data-act="refresh"]')?.classList.add('girando');
  await invoke('clear_catalog_cache');
  iconCache.clear();
  if (carga === 'error') { carga = 'cargando'; render(); }
  await loadApps();
  refrescando = false;
  $('#page [data-act="refresh"]')?.classList.remove('girando');
}

function cmpVer(a,b){
  const pa=a.split(/[.\-+]/).map(s=>parseInt(s,10)||0);
  const pb=b.split(/[.\-+]/).map(s=>parseInt(s,10)||0);
  for (let i=0;i<Math.max(pa.length,pb.length);i++){const x=pa[i]||0,y=pb[i]||0;if(x!==y) return x-y;}
  return 0;
}

function escapeHtml(s){return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

// ───── NAVEGACIÓN ─────
function ir(nueva) {
  ruta = nueva;
  currentApp = null;
  fallo = null;
  busqueda = '';
  $('#search').value = '';
  $('#search-x').classList.add('hidden');
  render(true);
}

function render(entrada=false) {
  renderSidebar();
  const page = $('#page');
  page.innerHTML = paginaHtml();
  if (entrada) {
    // Solo al navegar: un repintado por datos nuevos no repite la entrada.
    page.classList.remove('page-enter');
    void page.offsetWidth;
    page.classList.add('page-enter');
    page.parentElement.scrollTop = 0;
  }
  paintProgress();
}

function renderSidebar() {
  const cats = [...new Set(allApps.map(a => a.category))];
  const nUpd = allApps.filter(a => a.has_update).length;
  const item = (r, icono, texto, extra='') =>
    `<button class="item${!busqueda && ruta === r ? ' on' : ''}" data-ruta="${escapeHtml(r)}">${icono}<span class="item-text">${escapeHtml(texto)}</span>${extra}</button>`;
  $('#sb').innerHTML = `
    <div class="card">${item('discover', navIco('star', 'orange'), i18n('nav.discover'))}</div>
    ${cats.length ? `<div class="card">${cats.map((c, i) => item('cat:' + c, navIco('grid', COLORES_CAT[i % COLORES_CAT.length]), c)).join('')}</div>` : ''}
    <div class="card">
      ${item('installed', navIco('down', 'green'), i18n('nav.installed'))}
      ${item('updates', navIco('refresh', 'teal'), i18n('nav.updates'), nUpd ? `<span class="badge">${nUpd}</span>` : '')}
    </div>
    <div class="card">${item('settings', navIco('cog', 'gray'), i18n('nav.settings'))}</div>`;
}

const cabecera = (titulo, acciones='') => `
  <div class="page-header">
    <h2 class="page-title">${escapeHtml(titulo)}</h2>
    <div class="header-actions">${acciones}<button class="icon-btn${refrescando ? ' girando' : ''}" data-act="refresh" title="${escapeHtml(i18n('refresh'))}" aria-label="${escapeHtml(i18n('refresh'))}">${ico('refresh', 18)}</button></div>
  </div>`;

const estado = (icono, titulo, msg, extra='', cls='') => `
  <div class="detail-card state ${cls}">
    ${ico(icono, 40, 1.8)}
    <div class="state-title">${escapeHtml(titulo)}</div>
    <div class="state-msg">${escapeHtml(msg)}</div>
    ${extra}
  </div>`;

function paginaHtml() {
  // Ajustes no depende del catálogo: se abre aunque no haya cargado.
  if (ruta === 'settings' && !busqueda && !currentApp) return paginaAjustes();
  if (carga === 'cargando') return `
    <div class="skel">
      <div class="page-header"></div>
      <div class="skel-b" style="height:264px"></div>
      <div class="features"><div class="skel-b" style="height:128px;margin:0"></div><div class="skel-b" style="height:128px;margin:0"></div></div>
      <div class="skel-b" style="height:150px"></div>
    </div>`;
  if (carga === 'error') return cabecera(i18n('nav.discover')) + estado('warn', i18n('err.catalogTitle'), i18n('err.catalogMsg'),
    `<div class="state-motivo">${escapeHtml(motivoCarga)}</div><button class="btn primary" data-act="refresh">${i18n('retry')}</button>`, 'aviso');
  if (currentApp) return fichaHtml(currentApp);
  if (busqueda) return paginaBusqueda();
  if (ruta === 'installed') return paginaInstaladas();
  if (ruta === 'updates') return paginaActualizaciones();
  if (ruta.startsWith('cat:')) {
    const cat = ruta.slice(4);
    return cabecera(cat) + listaHtml(allApps.filter(a => a.category === cat));
  }
  return paginaDescubrir();
}

// ───── LISTAS ─────
// Qué ofrece una app en una fila: como mucho una acción.
function accionDe(a) {
  const compat = !!assetDe(a);
  if (a.has_update && compat) return { act: 'update', label: i18n('update'), cls: 'primary' };
  if (!a.installed) return compat ? { act: 'install', label: i18n('install'), cls: 'suave' } : null;
  if (!a.self) return { act: 'launch', label: i18n('open'), cls: 'suave' };
  return null;
}

function botonAccion(a, extra='') {
  const acc = accionDe(a);
  if (acc) return `<button class="btn ${acc.cls} ${extra} op-lock" data-act="${acc.act}" data-pkg="${escapeHtml(a.pkg)}">${acc.label}</button>`;
  if (a.installed) return `<span class="row-state ok">${ico('check', 14, 2.5)}${i18n('detail.upToDate')}</span>`;
  return `<span class="row-state" title="${escapeHtml(i18n('detail.noCompat', { pm: pmInfo.pm }))}">—</span>`;
}

const filaHtml = (a, sub) => `
  <div class="row nav" role="button" tabindex="0" data-abrir="${escapeHtml(a.pkg)}">
    ${iconHtml(a)}
    <div class="row-text">
      <div class="row-title">${escapeHtml(getLabel(a))}</div>
      <div class="row-sub">${escapeHtml(sub ?? getDesc(a))}</div>
    </div>
    ${botonAccion(a, 'small')}
  </div>`;

const listaHtml = (apps, sub) => `<div class="detail-card">${apps.map(a => filaHtml(a, sub?.(a))).join('')}</div>`;

function paginaDescubrir() {
  if (!allApps.length) return cabecera(i18n('nav.discover')) + estado('grid', i18n('empty.catalog'), i18n('empty.catalogMsg'),
    `<button class="btn" data-act="refresh">${i18n('recheck')}</button>`);
  // El catálogo no marca destacados: va delante lo publicado más recientemente.
  const recientes = [...allApps].sort((a, b) => (b.released || '').localeCompare(a.released || ''));
  const [d, ...resto] = recientes;
  const shot = (d.screenshots || [])[0];
  const cats = [...new Set(allApps.map(a => a.category))];
  return cabecera(i18n('nav.discover')) + `
    <div class="hero" role="button" tabindex="0" data-abrir="${escapeHtml(d.pkg)}">
      <div class="hero-text">
        <div class="eyebrow">${i18n(d.has_update ? 'hero.update' : 'hero.latest')}${d.available ? ' · ' + escapeHtml(d.available) : ''}</div>
        <div class="hero-title">${escapeHtml(getLabel(d))}</div>
        <div class="hero-desc">${escapeHtml(getDesc(d))}</div>
        ${accionDe(d) ? botonAccion(d) : ''}
      </div>
      <div class="hero-art">${shot ? `<img src="${escapeHtml(shot)}" alt="" draggable="false">` : iconHtml(d, 'xl')}</div>
    </div>
    <div class="features">${resto.slice(0, 2).map(a => `
      <div class="feature" role="button" tabindex="0" data-abrir="${escapeHtml(a.pkg)}">
        <div class="feature-text">
          <div class="eyebrow">${escapeHtml(a.category)}</div>
          <div class="feature-title">${escapeHtml(getLabel(a))}</div>
          <div class="feature-desc">${escapeHtml(getDesc(a))}</div>
        </div>
        ${iconHtml(a, 'l')}
      </div>`).join('')}
    </div>
    ${cats.map(c => `<div class="section-header">${escapeHtml(c)}</div>` + listaHtml(allApps.filter(a => a.category === c))).join('')}`;
}

function paginaBusqueda() {
  const q = busqueda.toLowerCase();
  const list = allApps.filter(a =>
    getLabel(a).toLowerCase().includes(q) ||
    a.pkg.toLowerCase().includes(q) ||
    getDesc(a).toLowerCase().includes(q));
  return cabecera(i18n('search.title', { q: busqueda })) + (list.length
    ? listaHtml(list)
    : estado('search', i18n('empty'), i18n('empty.searchMsg', { q: busqueda })));
}

function paginaInstaladas() {
  const list = allApps.filter(a => a.installed);
  return cabecera(i18n('nav.installed')) + (list.length
    ? listaHtml(list, a => a.manual ? i18n('detail.installedManual') : verCorta(a.installed))
    : estado('download', i18n('empty.installed'), i18n('empty.installedMsg')));
}

function paginaActualizaciones() {
  const list = allApps.filter(a => a.has_update);
  if (!list.length) return cabecera(i18n('nav.updates')) + operacionHtml() + estado('check', i18n('empty.updates'), i18n('empty.updatesMsg'));
  return cabecera(i18n('nav.updates'), `<button class="btn primary op-lock" data-act="update-all">${i18n('updateAll')}</button>`)
    + operacionHtml()
    + listaHtml(list, a => `${verCorta(a.installed)} → ${a.available}`);
}

// Aquí solo vive lo que es de la tienda. Idioma y tema son de todo el
// sistema: su único dueño es Ajustes de BookOS, y esta página lleva hasta allí.
const paginaAjustes = () => `
  <div class="page-header"><h2 class="page-title">${i18n('nav.settings')}</h2></div>
  <div class="detail-card">
    <div class="row">
      <div class="row-text">
        <div class="row-title">${i18n('settings.palette')}</div>
        <div class="row-sub">${i18n('settings.paletteSub')}</div>
      </div>
      <button class="toggle" role="switch" aria-checked="${window.bookosPalette.enabled()}" aria-label="${escapeHtml(i18n('settings.palette'))}" data-act="paleta"></button>
    </div>
  </div>
  <div class="detail-card">
    <div class="row nav" role="button" tabindex="0" data-act="ajustes-sistema">
      <div class="row-text">
        <div class="row-title">${i18n('settings.system')}</div>
        <div class="row-sub">${i18n('settings.systemSub')}</div>
      </div>
      ${ico('external', 16)}
    </div>
  </div>`;

// ───── FICHA ─────
async function openDetail(app) {
  if (!currentApp) scrollLista = $('#page').parentElement.scrollTop;
  currentApp = app;
  fallo = null;
  render(true);

  // Fetch full per-app detail (with releases history) from catalog endpoint.
  // Tauri client already cached catalog; here we hit the per-app endpoint
  // for the `releases[]` array which the grid response omits. Si falla, la
  // ficha se queda sin historial: lo demás ya viene en el listado.
  const full = await fetch('https://bookos.es/api/store.json?app=' + encodeURIComponent(app.pkg), { cache: 'no-store' })
    .then(r => r.ok ? r.json() : null)
    .catch(() => null);
  if (!full || currentApp?.pkg !== app.pkg) return;
  currentApp.releases = full.releases;
  render();
}

function closeDetail() {
  currentApp = null;
  fallo = null;
  closeLightbox();
  render(true);
  $('#page').parentElement.scrollTop = scrollLista;
}

const datoHtml = (titulo, valor) => valor ? `<div class="row"><div class="row-text"><div class="row-title">${titulo}</div></div><div class="row-val">${valor}</div></div>` : '';

function fichaHtml(a) {
  const pkg = escapeHtml(a.pkg);
  const compat = !!assetDe(a);
  const boton = (act, cls, icono, texto, title='') =>
    `<button class="btn ${cls} op-lock" data-act="${act}" data-pkg="${pkg}"${title ? ` title="${escapeHtml(title)}"` : ''}>${ico(icono, 14)}${texto}</button>`;

  let acciones = '';
  if (!a.installed) {
    acciones = compat
      ? boton('install', 'primary', 'download', i18n('install'))
      : `<button class="btn" disabled>${i18n('detail.noPkg', { pm: pmInfo.pm })}</button>`;
  } else if (a.manual) {
    // Binary present but not tracked by pm. Offer to register it (install via
    // the package manager so future updates work), plus launch.
    if (compat) acciones += boton('install', 'primary', 'download', i18n('detail.register'), i18n('detail.registerHint'));
    if (!a.self) acciones += boton('launch', '', 'play', i18n('open'));
  } else {
    if (a.has_update && compat) acciones += boton('update', 'primary', 'refresh', i18n('update'));
    if (!a.self) acciones += boton('launch', a.has_update ? '' : 'primary', 'play', i18n('open'));
    // Secundario, no rojo: el rojo va en el diálogo, que es donde se decide.
    if (!a.self) acciones += `<button class="btn op-lock" data-act="uninstall" data-pkg="${pkg}">${i18n('uninstall')}</button>`;
    if (a.self && !a.has_update) acciones += `<span class="row-state ok">${ico('check', 14, 2.5)}${i18n('detail.upToDate')}</span>`;
  }

  const shots = a.screenshots || [];
  const rels = a.releases || [];
  const notas = getNotes(rels[0] || a);
  const desc = getDesc(a) || i18n('detail.noDesc');

  return `
    <div class="page-header">
      <button class="back-btn" data-act="back" title="${escapeHtml(i18n('back'))}" aria-label="${escapeHtml(i18n('back'))}">${ico('left', 20, 2.5)}</button>
    </div>
    <div class="app-head">
      ${iconHtml(a, 'xl')}
      <div class="app-head-text">
        <h2 class="app-name">${escapeHtml(getLabel(a))}</h2>
        <div class="app-line">${[a.category, a.author].filter(Boolean).map(escapeHtml).join(' · ')}</div>
        <div class="app-actions">${acciones}</div>
      </div>
    </div>
    ${operacionHtml()}
    ${fallo && fallo.pkg === a.pkg ? `
    <div class="detail-card fallo">
      <div class="row">
        ${ico('warn', 22)}
        <div class="row-text">
          <div class="row-title">${escapeHtml(i18n('errIn', { stage: fallo.stage }))}</div>
          <div class="row-sub">${escapeHtml(fallo.file)}</div>
        </div>
        <button class="btn small op-lock" data-act="retry-op">${i18n('retry')}</button>
      </div>
      <pre class="fallo-log">${escapeHtml(fallo.msg)}</pre>
    </div>` : ''}
    ${shots.length ? `<div class="shots">${shots.map((s, i) => `
      <button class="shot" data-act="shot" data-i="${i}"><img src="${escapeHtml(s)}" alt="" loading="lazy" draggable="false"></button>`).join('')}</div>` : ''}
    <div class="section-header">${i18n('detail.about')}</div>
    <div class="detail-card prose">${formatMd(desc)}</div>
    ${notas ? `
    <div class="section-header">${i18n('detail.whatsNew')}${a.available ? ' · ' + escapeHtml(a.available) : ''}</div>
    <div class="detail-card prose">${formatMd(notas)}</div>` : ''}
    <div class="section-header">${i18n('detail.info')}</div>
    <div class="detail-card">
      ${datoHtml(i18n('detail.installedVer'), a.manual ? i18n('detail.installedManual') : a.installed ? escapeHtml(verCorta(a.installed)) : '')}
      ${datoHtml(i18n('detail.latestVer'), escapeHtml(a.available || '—'))}
      ${datoHtml(i18n('detail.released'), escapeHtml(a.released || ''))}
      ${datoHtml(i18n('detail.installedAt'), a.installed_at ? escapeHtml(new Date(a.installed_at * 1000).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })) : '')}
      ${datoHtml(i18n('detail.license'), escapeHtml(a.license || ''))}
      ${datoHtml(i18n('detail.package'), `<code>${pkg}</code>`)}
      ${a.html_url ? `<div class="row nav" role="button" tabindex="0" data-act="web" data-pkg="${pkg}"><div class="row-text"><div class="row-title">${i18n('detail.openHomepage')}</div></div>${ico('external', 16)}</div>` : ''}
    </div>
    ${rels.length > 1 ? `
    <div class="section-header">${i18n('detail.history')}</div>
    <div class="detail-card">${rels.map(r => {
      const n = getNotes(r);
      return `
      <div class="row rel">
        <div class="rel-head">
          <span class="row-title">${escapeHtml(r.version)}</span>
          ${r.channel && r.channel !== 'stable' ? `<span class="chip">${escapeHtml(r.channel)}</span>` : ''}
          <span class="rel-date">${escapeHtml(r.released || '')}</span>
        </div>
        <div class="rel-notes">${n ? formatMd(n) : i18n('detail.noNotes')}</div>
      </div>`;
    }).join('')}</div>` : ''}`;
}

// Tiny markdown: bold **x**, links, line breaks. Safer than dropping innerHTML raw.
function formatMd(s) {
  if (!s) return '';
  // Escape first, then re-apply safe tags.
  let out = escapeHtml(s);
  out = out.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  out = out.replace(/`([^`]+)`/g, '<code>$1</code>');
  // Bullet lines starting with "- "
  out = out.replace(/^- (.+)$/gm, '• $1');
  // Paragraphs from double newline, <br> from single
  out = out.split(/\n{2,}/).map(p => '<p>' + p.replace(/\n/g, '<br>') + '</p>').join('');
  return out;
}

// ───── LIGHTBOX ─────
function openLightbox(idx) {
  lightboxIdx = idx;
  let lb = $('#lightbox');
  if (!lb) {
    lb = document.createElement('div');
    lb.id = 'lightbox';
    lb.className = 'lightbox';
    lb.innerHTML = `
      <button class="lb-btn" id="lb-close" aria-label="${escapeHtml(i18n('close'))}">${ico('close', 20)}</button>
      <button class="lb-btn" id="lb-prev" aria-label="${escapeHtml(i18n('lb.prev'))}">${ico('left', 20)}</button>
      <img id="lb-img" alt="">
      <button class="lb-btn" id="lb-next" aria-label="${escapeHtml(i18n('lb.next'))}">${ico('right', 20)}</button>
      <div class="lb-counter" id="lb-counter"></div>
    `;
    document.body.appendChild(lb);
    lb.querySelector('#lb-close').addEventListener('click', closeLightbox);
    lb.querySelector('#lb-prev').addEventListener('click', () => stepLightbox(-1));
    lb.querySelector('#lb-next').addEventListener('click', () => stepLightbox(+1));
    lb.addEventListener('click', e => { if (e.target === lb) closeLightbox(); });
  }
  updateLightbox();
  lb.classList.remove('hidden');
}
function updateLightbox() {
  const lb = $('#lightbox');
  const shots = currentApp.screenshots || [];
  lb.querySelector('#lb-img').src = shots[lightboxIdx] || '';
  lb.querySelector('#lb-counter').textContent = `${lightboxIdx+1} / ${shots.length}`;
  lb.querySelector('#lb-prev').style.visibility = lightboxIdx > 0 ? 'visible' : 'hidden';
  lb.querySelector('#lb-next').style.visibility = lightboxIdx < shots.length-1 ? 'visible' : 'hidden';
}
function stepLightbox(d) {
  const shots = currentApp.screenshots || [];
  lightboxIdx = Math.max(0, Math.min(shots.length-1, lightboxIdx + d));
  updateLightbox();
}
function closeLightbox() { lightboxIdx = -1; $('#lightbox')?.classList.add('hidden'); }

// ───── ACTIONS ─────
async function doLaunch(app) {
  try { await invoke('launch_app', { pkg: app.pkg }); toast(i18n('launching', { app: getLabel(app) })); }
  catch (e) { toast(i18n('err', { m: errMsg(e) })); }
}

let currentOpId = null;
let progressTimer = null;
function newOpId() { return 'op-' + Math.random().toString(36).slice(2,10) + '-' + Date.now(); }

function startProgressPoll(opId) {
  stopProgressPoll();
  progressTimer = setInterval(async () => {
    const p = await invoke('progress', { opId }).catch(() => null);
    if (!p || !p.active) { stopProgressPoll(); return; }
    if (!op) return;
    op.pct = Math.max(0, Math.min(100, p.pct || 0));
    if (p.total > 0) op.text = i18n('downloadingPct', { pct: op.pct.toFixed(0), dn: fmtBytes(p.downloaded), total: fmtBytes(p.total) });
    paintProgress();
  }, 250);
}
function stopProgressPoll() { if (progressTimer) { clearInterval(progressTimer); progressTimer = null; } }
function fmtBytes(b) {
  if (!b) return '0 B';
  const u = ['B','KB','MB','GB']; let i = 0;
  while (b >= 1024 && i < u.length-1) { b /= 1024; i++; }
  return b.toFixed(b<10?1:0) + ' ' + u[i];
}

async function doInstall(app, isUpdate=false) {
  const asset = assetDe(app);
  if (!asset) {
    toast(i18n('noPkg', { exts: (pmInfo.exts||['.pkg.tar.zst']).join('/') }));
    return;
  }
  const pwd = await promptAuth(
    isUpdate ? i18n('auth.titleUpdate') : i18n('auth.titleInstall'),
    i18n(isUpdate ? 'auth.descUpdate' : 'auth.descInstall', { app: getLabel(app) }));
  if (pwd === null) return;
  const opId = newOpId();
  currentOpId = opId;
  fallo = null;
  render();
  setProgress(true, i18n('downloadingFile', { f: asset.name }), true);
  startProgressPoll(opId);
  let stage = i18n('stage.download');
  try {
    const localPath = await invoke('download_pkg', { url: asset.browser_download_url, filename: asset.name, sha256: asset.sha256 || null, opId });
    stopProgressPoll();
    setProgress(true, i18n('installingWith', { pm: pmInfo.pm || 'pm' }), false);
    stage = i18n('stage.install');
    await invoke('install_pkg_file', { path: localPath, pkg: app.pkg, password: pwd, opId });
    currentOpId = null;
    if (app.self && isUpdate) {
      toast(i18n('selfUpdate'));
      setTimeout(() => tauriWin().close(), 1400);
      return;
    }
    op = null;
    toast(i18n(isUpdate?'updatedToast':'installedToast', { app: getLabel(app) }));
    await loadApps();
  } catch (e) {
    stopProgressPoll();
    currentOpId = null;
    op = null;
    const msg = errMsg(e);
    if (msg.includes('__cancelled__')) toast(i18n('cancelledOp'));
    else fallo = { pkg: app.pkg, stage, file: asset.name, msg, retry: () => doInstall(app, isUpdate) };
    render();
  }
}

async function doUninstall(app) {
  const pwd = await promptAuth(i18n('auth.titleUninstall'),
    i18n('auth.descUninstall', { app: getLabel(app), pkg: app.pkg }),
    { ok: i18n('uninstall'), danger: true });
  if (pwd === null) return;
  const opId = newOpId();
  currentOpId = opId;
  fallo = null;
  render();
  setProgress(true, i18n('uninstalling'), false);
  try {
    await invoke('uninstall_pkg', { pkg: app.pkg, password: pwd, opId });
    currentOpId = null;
    op = null;
    toast(i18n('uninstalledToast', { app: getLabel(app) }));
    await loadApps();
  } catch (e) {
    currentOpId = null;
    op = null;
    const msg = errMsg(e);
    if (msg.includes('__cancelled__')) toast(i18n('cancelledOp'));
    else fallo = { pkg: app.pkg, stage: i18n('stage.uninstall'), file: app.pkg, msg, retry: () => doUninstall(app) };
    render();
  }
}

async function cancelCurrentOp() {
  if (!currentOpId) return;
  await invoke('cancel_op', { opId: currentOpId });
}

async function doUpdateAll() {
  const list = allApps.filter(a => a.has_update);
  if (list.length === 0) return;
  const pwd = await promptAuth(i18n('auth.titleUpdateAll'),
    i18n('auth.descUpdateAll', { n: list.length }));
  if (pwd === null) return;
  let needsRestart = false;
  for (const app of list) {
    const asset = assetDe(app);
    if (!asset) { toast(i18n('skipNoPkg', { app: getLabel(app) })); continue; }
    const opId = newOpId();
    currentOpId = opId;
    setProgress(true, i18n('downloadingFile', { f: asset.name }), true);
    startProgressPoll(opId);
    try {
      const localPath = await invoke('download_pkg', { url: asset.browser_download_url, filename: asset.name, sha256: asset.sha256 || null, opId });
      stopProgressPoll();
      setProgress(true, i18n('installingApp', { app: getLabel(app) }), false);
      await invoke('install_pkg_file', { path: localPath, pkg: app.pkg, password: pwd, opId });
      toast(i18n('updatedToast', { app: getLabel(app) }));
      if (app.self) needsRestart = true;
    } catch (e) {
      stopProgressPoll();
      const msg = errMsg(e);
      if (msg.includes('__cancelled__')) { toast(i18n('cancelled')); break; }
      toast(i18n('err', { m: getLabel(app) + ': ' + msg.slice(0,100) }));
    }
  }
  currentOpId = null;
  setProgress(false);
  if (needsRestart) {
    toast(i18n('selfUpdate'));
    setTimeout(() => tauriWin().close(), 1400);
    return;
  }
  await loadApps();
}

// ───── AUTH DIALOG ─────
function promptAuth(title, desc, { ok = i18n('auth.ok'), danger = false } = {}) {
  return new Promise(resolve => {
    const ov = $('#auth-overlay');
    const input = $('#auth-input');
    const err = $('#auth-err');
    const okBtn = $('#auth-ok'), cancelBtn = $('#auth-cancel'), eyeBtn = $('#auth-eye');
    $('#auth-title').textContent = title;
    $('#auth-desc').textContent = desc;
    okBtn.textContent = ok;
    okBtn.className = 'bk-btn ' + (danger ? 'danger' : 'primary');
    input.value = ''; input.type = 'password';
    err.classList.add('hidden');
    ov.classList.remove('hidden');
    setTimeout(() => input.focus(), 60);

    const cleanup = (val) => {
      ov.classList.add('hidden');
      okBtn.removeEventListener('click', onOk);
      cancelBtn.removeEventListener('click', onCancel);
      input.removeEventListener('keydown', onKey);
      eyeBtn.removeEventListener('click', onEye);
      ov.removeEventListener('click', onBg);
      resolve(val);
    };
    const onOk = async () => {
      const p = input.value;
      if (!p) { err.textContent = i18n('auth.emptyPass'); err.classList.remove('hidden'); return; }
      okBtn.disabled = true;
      const valida = await invoke('verify_password', { password: p });
      okBtn.disabled = false;
      if (!valida) { err.textContent = i18n('auth.err'); err.classList.remove('hidden'); input.select(); return; }
      cleanup(p);
    };
    const onCancel = () => cleanup(null);
    const onKey = (e) => { if (e.key==='Enter') onOk(); else if (e.key==='Escape') { e.stopPropagation(); onCancel(); } };
    const onEye = () => { input.type = input.type==='password'?'text':'password'; };
    const onBg = (e) => { if (e.target.id==='auth-overlay') onCancel(); };
    okBtn.addEventListener('click', onOk);
    cancelBtn.addEventListener('click', onCancel);
    input.addEventListener('keydown', onKey);
    eyeBtn.addEventListener('click', onEye);
    ov.addEventListener('click', onBg);
  });
}

// ───── PROGRESO ─────
// El estado vive en `op` y no en el DOM: la página se repinta mientras dura
// una operación (llega el historial, se navega) y la barra tiene que seguir ahí.
const operacionHtml = () => `
  <div class="detail-card op hidden" id="op-progress">
    <div class="op-bar"><div class="op-fill" id="op-fill"></div></div>
    <div class="op-row">
      <div class="op-text" id="op-text"></div>
      <button class="btn small hidden" data-act="cancel" id="op-cancel">${i18n('cancel')}</button>
    </div>
  </div>`;

function setProgress(on, text, cancellable=false) {
  op = on ? { text, pct: cancellable ? 0 : null, cancellable } : null;
  paintProgress();
}

function paintProgress() {
  document.querySelectorAll('#page .op-lock').forEach(b => b.disabled = !!op);
  const p = $('#op-progress');
  if (!p) return;
  p.classList.toggle('hidden', !op);
  if (!op) return;
  $('#op-text').textContent = op.text;
  const fill = $('#op-fill');
  fill.classList.toggle('indet', op.pct === null);
  fill.style.transform = op.pct === null ? '' : `scaleX(${op.pct / 100})`;
  $('#op-cancel').classList.toggle('hidden', !op.cancellable);
}

// ───── WIRE ─────
function accion(act, el) {
  const app = allApps.find(a => a.pkg === el.dataset.pkg);
  switch (act) {
    case 'back':       closeDetail(); break;
    case 'refresh':    refrescar(); break;
    case 'update-all': doUpdateAll(); break;
    case 'cancel':     cancelCurrentOp(); break;
    case 'retry-op':   fallo.retry(); break;
    case 'paleta': {
      const on = el.getAttribute('aria-checked') !== 'true';
      window.bookosPalette.setEnabled(on);
      el.setAttribute('aria-checked', on);
      break;
    }
    case 'ajustes-sistema': invoke('launch_app', { pkg: 'bookos-settings' }).catch(e => toast(i18n('err', { m: errMsg(e) }))); break;
    case 'shot':       openLightbox(+el.dataset.i); break;
    case 'web':        invoke('open_release_page').catch(e => toast(i18n('err', { m: errMsg(e) }))); break;
    case 'launch':     doLaunch(app); break;
    case 'uninstall':  doUninstall(app); break;
    // La barra de progreso vive en la ficha: instalar desde una fila la abre.
    case 'install':
    case 'update':
      if (currentApp?.pkg !== app.pkg) openDetail(app);
      doInstall(app, act === 'update');
      break;
  }
}

function wire() {
  $('#minimize').addEventListener('click', () => tauriWin().minimize());
  $('#maximize').addEventListener('click', () => tauriWin().toggleMaximize());
  $('#close').addEventListener('click', () => tauriWin().close());

  $('#sb').addEventListener('click', e => {
    const it = e.target.closest('[data-ruta]');
    if (it) ir(it.dataset.ruta);
  });

  const pulsar = e => {
    const b = e.target.closest('[data-act]');
    if (b) { if (!b.disabled) accion(b.dataset.act, b); return; }
    const fila = e.target.closest('[data-abrir]');
    if (fila) openDetail(allApps.find(a => a.pkg === fila.dataset.abrir));
  };
  $('#page').addEventListener('click', pulsar);
  // Las filas son <div role="button"> (llevan un <button> dentro): Enter a mano.
  $('#page').addEventListener('keydown', e => {
    if (e.key === 'Enter' && e.target.matches('[role="button"]')) pulsar(e);
  });

  const search = $('#search');
  const limpiar = () => { search.value = ''; search.dispatchEvent(new Event('input')); };
  search.addEventListener('input', () => {
    const antes = busqueda;
    busqueda = search.value.trim();
    $('#search-x').classList.toggle('hidden', !search.value);
    if (busqueda) currentApp = null;
    // Entrar o salir de la búsqueda es navegar; afinar lo escrito, no.
    render(!antes !== !busqueda);
  });
  search.addEventListener('keydown', e => { if (e.key === 'Escape' && search.value) { e.stopPropagation(); limpiar(); } });
  $('#search-x').addEventListener('click', () => { limpiar(); search.focus(); });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      if (lightboxIdx >= 0) { closeLightbox(); return; }
      if (currentApp) closeDetail();
    }
    if ((e.ctrlKey||e.metaKey) && e.key === 'f') { e.preventDefault(); search.focus(); }
    if (lightboxIdx >= 0 && (e.key === 'ArrowLeft' || e.key === 'ArrowRight')) {
      stepLightbox(e.key === 'ArrowLeft' ? -1 : +1);
    }
  });

  // Ajustes puede cambiar idioma o tema con la tienda abierta. Se relee al
  // recuperar el foco, igual que hace bookos-palette.js con la paleta.
  window.addEventListener('focus', async () => {
    applyTheme();
    const l = await invoke('bookos_language').catch(() => lang());
    if (l !== lang()) { BookosI18n.setLang(l); render(); }
  });
}

(async function init(){
  BookosI18n.setLang(await invoke('bookos_language').catch(() => 'es'));
  await applyTheme();
  matchMedia('(prefers-color-scheme: dark)').addEventListener('change', applyTheme);
  wire();
  render();
  await loadApps();
})();

import React, { useState, useEffect, useRef } from 'react';
import { useParams, useLocation } from 'react-router-dom';

const API_BASE = '/api/v1/analysis';
const STOPPED_MESSAGE = 'Остановлен принудительно нажатием на кнопку "Остановить анализ"';
const LAST_MODEL_KEY = 'cve-verdict-last-model';

const readLastModel = () => {
  try {
    return (localStorage.getItem(LAST_MODEL_KEY) || '').trim();
  } catch {
    return '';
  }
};

const rememberModel = (model) => {
  const name = (model || '').trim();
  if (!name) return;
  try {
    localStorage.setItem(LAST_MODEL_KEY, name);
  } catch {
    // Запуск не зависит от того, смог ли браузер сохранить выбор.
  }
};

const apiService = {
  createTask: async (data) => {
    const res = await fetch(API_BASE, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        component_url: data.url,
        branch: data.branch,
        cve_id: data.cveId,
        package_name: data.packageName,
        model: data.model
      })
    });

    const json = await res.json();

    if (!res.ok) {
      throw new Error(json.error || `Ошибка сервера (${res.status})`);
    }

    return json;
  },

  getTasks: async (limit = 10, offset = 0, filter = {}) => {
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    if (filter.url) params.set('component_url', filter.url);
    if (filter.branch) params.set('branch', filter.branch);
    if (filter.cveId) params.set('cve_id', filter.cveId);
    if (filter.packageName) params.set('package_name', filter.packageName);
    if (filter.status) params.set('status', filter.status);
    if (filter.applicability) params.set('applicability', filter.applicability);
    const res = await fetch(`${API_BASE}?${params}`);
    if (!res.ok) throw new Error('Failed to fetch tasks');
    const data = await res.json();
    return {
      list: data.items || [],
      total: parseInt(data.total, 10) || 0
    };
  },

  getTaskDetails: async (id) => {
    const res = await fetch(`${API_BASE}/${id}`);
    if (!res.ok) throw new Error('Failed to fetch details');
    return res.json();
  },

  downloadReportUrl: (id) => `${API_BASE}/${id}/report`,

  saveReview: async (id, data) => {
    const res = await fetch(`${API_BASE}/${id}/review`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rating: data.rating, review: data.review || '' })
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(json.error || `Ошибка сервера (${res.status})`);
    return json;
  },

  getReviews: async (limit = 10, offset = 0) => {
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    const res = await fetch(`${API_BASE}/reviews?${params}`);
    const json = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(json.error || 'Не удалось загрузить отзывы');
    return json;
  },

  stopTask: async (id) => {
    const res = await fetch(`${API_BASE}/${id}/cancel`, { method: 'POST' });
    const json = await res.json().catch(() => ({}));
    if (res.status === 409) throw new Error('Анализ уже завершился');
    if (res.status === 404) throw new Error('Анализ не найден');
    if (!res.ok) throw new Error(json.error || `Ошибка сервера (${res.status})`);
    return json;
  },

  getDefaultModel: async () => {
    const res = await fetch(`${API_BASE}/default-model`);
    if (!res.ok) throw new Error('Failed to fetch default model');
    const data = await res.json();
    return data.model || '';
  },

  listModels: async () => {
    const res = await fetch(`${API_BASE}/models`);
    const json = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(json.error || 'Не удалось получить список моделей');
    return json.models || [];
  },

  getCurrentGo: async () => {
    const res = await fetch(`${API_BASE}/go-version`);
    if (!res.ok) throw new Error('Failed to fetch Go version');
    const data = await res.json();
    return data.version || '';
  },

  suggestProjects: async (q) => {
    const params = new URLSearchParams({ q: q || '' });
    const res = await fetch(`${API_BASE}/projects?${params}`);
    if (!res.ok) return [];
    const data = await res.json();
    return data.items || [];
  },

  suggestBranches: async (url, q) => {
    if (!url) return [];
    const params = new URLSearchParams({ component_url: url, q: q || '' });
    const res = await fetch(`${API_BASE}/branches?${params}`);
    if (!res.ok) return [];
    const data = await res.json();
    return data.items || [];
  }
};

// --- THEME & STYLES ---
const theme = {
  pageBg: '#EAF2F8', boardBg: '#F4F8FB', textMain: '#1E293B', textMuted: '#64748B',
  primary: '#2563EB', primaryHover: '#1D4ED8', primaryLight: '#DBEAFE',
  border: '#CBD5E1', borderDark: '#94A3B8',
  shadowBoard: '0 25px 50px -12px rgba(30, 41, 59, 0.1)',
  success: { bg: '#ECFDF5', text: '#065F46', accent: '#10B981', border: '#A7F3D0' },
  error: { bg: '#FEF2F2', text: '#991B1B', accent: '#EF4444', border: '#FECACA' },
  pending: { bg: '#F1F5F9', text: '#475569', accent: '#94A3B8', border: '#E2E8F0' },
  running: { bg: '#FFEDD5', text: '#C2410C', accent: '#F97316', border: '#FDBA74' },
  uncertain: { bg: '#FFFBEB', text: '#92400E', accent: '#D97706', border: '#FDE68A' }
};

const fullPageStyle = { width: '100%', minHeight: '100vh', backgroundColor: theme.pageBg, display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '3rem 1rem' };
const boardContainerStyle = { width: '100%', maxWidth: '1200px', backgroundColor: theme.boardBg, borderRadius: '1.5rem', border: `1px solid #D6E0EA`, boxShadow: theme.shadowBoard, padding: '3.5rem', boxSizing: 'border-box', position: 'relative' };
const innerCardStyle = { backgroundColor: 'rgba(255, 255, 255, 0.6)', backdropFilter: 'blur(8px)', borderRadius: '1rem', border: `1px solid rgba(203, 213, 225, 0.6)`, padding: '2rem' };

const navBtnGroupStyle = { display: 'flex', gap: '0.75rem', flexShrink: 0 };
const listNavBtnStyle = {
  display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem',
  padding: '0.85rem 1.5rem', borderRadius: '0.75rem',
  border: `2px solid ${theme.primary}`, background: '#FFFFFF',
  color: theme.primary, fontSize: '1rem', fontWeight: '700',
  cursor: 'pointer', transition: 'all 0.2s ease', height: '48px'
};
const backBtnStyle = {
  display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem',
  padding: '0.85rem 1.5rem', borderRadius: '0.75rem',
  border: `1px solid ${theme.borderDark}`, background: 'transparent',
  color: theme.textMuted, fontSize: '1rem', fontWeight: '600',
  cursor: 'pointer', transition: 'all 0.2s ease', height: '48px'
};

const applicabilityView = (value, scope = 'task') => {
  const views = {
    applicable: {
      label: 'Применима',
      colors: theme.error,
      mark: '!',
      hint: scope === 'module'
        ? 'В этом модуле уязвимый код нашёлся'
        : 'Хотя бы в одном модуле уязвимость применима'
    },
    not_applicable: {
      label: 'Неприменима',
      colors: theme.success,
      mark: '✓',
      hint: scope === 'module'
        ? 'В этом модуле уязвимость неприменима'
        : 'Во всех модулях уязвимость неприменима'
    },
    uncertain: {
      label: 'Неопределенно',
      colors: theme.uncertain,
      mark: '?',
      hint: scope === 'module'
        ? 'По этому модулю вывод не уверенный'
        : 'Применимых модулей нет, но хотя бы один вывод не уверенный'
    }
  };
  return views[value] || null;
};

const formatDuration = (ms) => {
  if (ms == null || ms === '') return '';
  const n = Number(ms);
  if (!Number.isFinite(n) || n < 0) return '';
  if (n < 1000) return `${Math.round(n)} мс`;
  const totalSec = Math.round(n / 1000);
  const hours = Math.floor(totalSec / 3600);
  const minutes = Math.floor((totalSec % 3600) / 60);
  const seconds = totalSec % 60;
  const two = (value) => String(value).padStart(2, '0');
  if (hours > 0) return minutes ? `${hours} ч ${two(minutes)} мин` : `${hours} ч`;
  if (minutes > 0) return `${two(minutes)} мин ${two(seconds)} с`;
  return `${two(seconds)} с`;
};

const showDuration = (status, ms) => status && status !== 'PENDING' && formatDuration(ms) !== '';

const emptySearch = { url: '', branch: '', cveId: '', packageName: '', result: '' };

const searchParams = (search) => {
  const params = {};
  if (!search) return params;
  if (search.url) params.url = search.url;
  if (search.branch) params.branch = search.branch;
  if (search.cveId) params.cveId = search.cveId;
  if (search.packageName) params.packageName = search.packageName;
  if (search.result === 'PENDING' || search.result === 'RUNNING' || search.result === 'FAILED') {
    params.status = search.result;
  } else if (search.result) {
    params.applicability = search.result;
  }
  return params;
};

const searchFilled = (search) => Boolean(
  search && (search.url || search.branch || search.cveId || search.packageName || search.result)
);

const pillStyle = (colors) => ({
  display: 'inline-flex',
  alignItems: 'center',
  gap: '0.4rem',
  padding: '0.35rem 0.85rem',
  borderRadius: '9999px',
  fontSize: '0.85rem',
  fontWeight: '700',
  backgroundColor: colors.bg,
  color: colors.text,
  border: `1px solid ${colors.border}`,
  whiteSpace: 'nowrap'
});

const ClockIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <circle cx="12" cy="12" r="10" />
    <polyline points="12 6 12 12 16 14" />
  </svg>
);

function ModelPicker({ value, onChange }) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [models, setModels] = useState([]);
  const [error, setError] = useState('');
  const boxRef = useRef(null);

  useEffect(() => {
    if (!open) return undefined;
    const close = (event) => {
      if (boxRef.current && !boxRef.current.contains(event.target)) setOpen(false);
    };
    document.addEventListener('mousedown', close);
    return () => document.removeEventListener('mousedown', close);
  }, [open]);

  const openList = async () => {
    if (open) {
      setOpen(false);
      return;
    }
    setOpen(true);
    setLoading(true);
    setError('');
    setModels([]);
    try {
      const list = await apiService.listModels();
      setModels(list);
    } catch (err) {
      setError(err.message || 'Не удалось получить список моделей');
    } finally {
      setLoading(false);
    }
  };

  const label = value || 'не выбрана';

  return (
    <div ref={boxRef} style={{ position: 'relative', flexShrink: 0 }}>
      <button
        type="button"
        title={value || 'Выбрать модель'}
        aria-expanded={open}
        aria-haspopup="listbox"
        onClick={openList}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '0.7rem',
          maxWidth: '280px',
          padding: '0.4rem 0.45rem 0.4rem 0.85rem',
          borderRadius: '0.9rem',
          border: `1.5px solid ${open ? theme.primary : '#BFDBFE'}`,
          background: open ? '#FFFFFF' : 'linear-gradient(180deg, #FFFFFF 0%, #F8FBFF 100%)',
          boxShadow: open ? `0 0 0 4px ${theme.primaryLight}` : '0 8px 18px -14px rgba(37, 99, 235, 0.9)',
          color: theme.textMain,
          cursor: 'pointer',
          transition: 'border-color 0.15s ease, box-shadow 0.15s ease'
        }}
        onMouseEnter={e => {
          if (!open) {
            e.currentTarget.style.borderColor = theme.primary;
            e.currentTarget.style.boxShadow = `0 0 0 4px ${theme.primaryLight}`;
          }
        }}
        onMouseLeave={e => {
          if (!open) {
            e.currentTarget.style.borderColor = '#BFDBFE';
            e.currentTarget.style.boxShadow = '0 8px 18px -14px rgba(37, 99, 235, 0.9)';
          }
        }}
      >
        <span style={{ minWidth: 0, textAlign: 'left' }}>
          <span style={{ display: 'block', fontSize: '0.68rem', fontWeight: '800', letterSpacing: '0.06em', textTransform: 'uppercase', color: theme.primary, lineHeight: 1.2 }}>Модель</span>
          <span style={{ display: 'block', maxWidth: '168px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: '0.92rem', fontWeight: '600', lineHeight: 1.3 }}>{label}</span>
        </span>
        <span style={{
          width: '28px',
          height: '28px',
          borderRadius: '0.6rem',
          background: open ? theme.primary : theme.primaryLight,
          color: open ? '#fff' : theme.primary,
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0,
          transition: 'transform 0.18s ease, background 0.18s ease',
          transform: open ? 'rotate(180deg)' : 'none'
        }}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <polyline points="6 9 12 15 18 9" />
          </svg>
        </span>
      </button>
      {open && (
        <div
          role="listbox"
          style={{
            position: 'absolute',
            top: 'calc(100% + 0.5rem)',
            right: 0,
            zIndex: 20,
            width: '320px',
            maxHeight: '320px',
            overflow: 'auto',
            background: '#fff',
            border: `1px solid ${theme.primary}`,
            borderRadius: '1rem',
            boxShadow: '0 22px 44px -20px rgba(30, 41, 59, 0.45)',
            padding: '0.45rem'
          }}
        >
          {loading && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem', padding: '1rem 0.85rem', color: theme.primary }}>
              <span style={{
                width: '22px',
                height: '22px',
                borderRadius: '50%',
                border: `2.5px solid ${theme.primaryLight}`,
                borderTopColor: theme.primary,
                flexShrink: 0,
                animation: 'spin 0.8s linear infinite'
              }} />
              <span style={{ fontWeight: '700', fontSize: '0.95rem', lineHeight: 1.4 }}>Ожидаем получения списка моделей</span>
            </div>
          )}
          {!loading && error && (
            <div style={{ margin: '0.25rem', padding: '0.9rem 0.85rem', borderRadius: '0.75rem', background: theme.error.bg, color: theme.error.text, fontWeight: '700', fontSize: '0.92rem', lineHeight: 1.45 }}>
              {error}
            </div>
          )}
          {!loading && !error && models.length === 0 && (
            <div style={{ padding: '1rem 0.85rem', color: theme.textMuted, fontWeight: '700', fontSize: '0.92rem' }}>
              Список моделей пуст
            </div>
          )}
          {!loading && !error && models.map((name) => {
            const selected = name === value;
            return (
              <button
                key={name}
                type="button"
                role="option"
                aria-selected={selected}
                onClick={() => { onChange(name); setOpen(false); }}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.7rem',
                  width: '100%',
                  textAlign: 'left',
                  padding: '0.72rem 0.75rem',
                  border: 'none',
                  borderRadius: '0.7rem',
                  background: selected ? theme.primaryLight : 'transparent',
                  color: selected ? theme.primary : theme.textMain,
                  fontWeight: '600',
                  fontSize: '0.92rem',
                  cursor: 'pointer'
                }}
                onMouseEnter={e => { if (!selected) e.currentTarget.style.backgroundColor = '#F8FAFC'; }}
                onMouseLeave={e => { if (!selected) e.currentTarget.style.backgroundColor = 'transparent'; }}
              >
                <span style={{
                  width: '18px',
                  height: '18px',
                  borderRadius: '50%',
                  border: `1.5px solid ${selected ? theme.primary : theme.borderDark}`,
                  background: selected ? theme.primary : '#fff',
                  color: '#fff',
                  display: 'inline-flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexShrink: 0
                }}>
                  {selected && (
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                      <polyline points="20 6 9 17 4 12" />
                    </svg>
                  )}
                </span>
                <span style={{ minWidth: 0, wordBreak: 'break-word' }}>{name}</span>
              </button>
            );
          })}
        </div>
      )}
      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}

const fieldInputStyle = {
  border: `1px solid ${theme.border}`,
  borderRadius: '0.75rem',
  padding: '1.1rem 1.35rem',
  fontSize: '1.1rem',
  width: '100%',
  boxSizing: 'border-box',
  outline: 'none',
  backgroundColor: 'rgba(255,255,255,0.8)',
  transition: 'all 0.2s',
  color: theme.textMain
};

function SuggestField({ label, placeholder, value, onChange, load, reloadKey, onPick, itemKey, itemText, itemHint }) {
  const [open, setOpen] = useState(false);
  const [items, setItems] = useState([]);
  const [active, setActive] = useState(-1);
  const boxRef = useRef(null);
  const timer = useRef(null);
  const seq = useRef(0);

  const run = (text) => {
    const id = ++seq.current;
    Promise.resolve()
      .then(() => load(text))
      .then((list) => {
        if (id !== seq.current) return;
        setItems(Array.isArray(list) ? list : []);
        setActive(-1);
      })
      .catch(() => {
        if (id !== seq.current) return;
        setItems([]);
      });
  };

  const schedule = (text) => {
    clearTimeout(timer.current);
    timer.current = setTimeout(() => run(text), 250);
  };

  useEffect(() => () => clearTimeout(timer.current), []);

  useEffect(() => {
    if (!open) return undefined;
    schedule(value);
    return undefined;
  }, [reloadKey]);

  const choose = (item) => {
    setOpen(false);
    setItems([]);
    onPick(item);
  };

  const onKeyDown = (event) => {
    if (event.key === 'Escape') {
      setOpen(false);
      return;
    }
    if (!open || items.length === 0) return;
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      setActive((index) => (index + 1) % items.length);
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      setActive((index) => (index <= 0 ? items.length - 1 : index - 1));
    } else if (event.key === 'Enter' && active >= 0) {
      event.preventDefault();
      choose(items[active]);
    }
  };

  return (
    <div ref={boxRef} style={{ marginBottom: '2rem', position: 'relative' }}>
      <label style={{ display: 'block', fontSize: '1.05rem', fontWeight: '700', marginBottom: '0.85rem', color: theme.textMain }}>
        {label} <span style={{ color: '#DC2626' }}>*</span>
      </label>
      <input
        value={value}
        placeholder={placeholder}
        autoComplete="off"
        aria-autocomplete="list"
        aria-expanded={open && items.length > 0}
        style={fieldInputStyle}
        onChange={(event) => {
          onChange(event.target.value);
          setOpen(true);
          schedule(event.target.value);
        }}
        onFocus={(event) => {
          setOpen(true);
          run(value);
          event.target.style.borderColor = theme.primary;
          event.target.style.boxShadow = `0 0 0 4px ${theme.primaryLight}`;
        }}
        onBlur={(event) => {
          event.target.style.borderColor = theme.border;
          event.target.style.boxShadow = 'none';
          setTimeout(() => setOpen(false), 120);
        }}
        onKeyDown={onKeyDown}
      />
      {open && items.length > 0 && (
        <div
          role="listbox"
          style={{
            position: 'absolute',
            left: 0,
            right: 0,
            top: '100%',
            marginTop: '0.4rem',
            background: '#fff',
            border: `1px solid ${theme.border}`,
            borderRadius: '0.75rem',
            boxShadow: '0 12px 30px rgba(30, 41, 59, 0.12)',
            zIndex: 20,
            maxHeight: '16rem',
            overflowY: 'auto'
          }}
        >
          {items.map((item, index) => {
            const hint = itemHint(item);
            const selected = index === active;
            return (
              <button
                type="button"
                role="option"
                aria-selected={selected}
                key={itemKey(item)}
                onMouseDown={(event) => event.preventDefault()}
                onClick={() => choose(item)}
                onMouseEnter={() => setActive(index)}
                style={{
                  display: 'block',
                  width: '100%',
                  textAlign: 'left',
                  border: 'none',
                  borderBottom: index === items.length - 1 ? 'none' : `1px solid ${theme.border}`,
                  background: selected ? theme.primaryLight : '#fff',
                  padding: '0.85rem 1.1rem',
                  cursor: 'pointer',
                  color: theme.textMain
                }}
              >
                <span style={{ display: 'block', fontWeight: '700', fontSize: '1rem' }}>{itemText(item)}</span>
                {hint && <span style={{ display: 'block', marginTop: '0.2rem', color: theme.textMuted, fontSize: '0.9rem' }}>{hint}</span>}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

function blameError(message) {
  if (message === STOPPED_MESSAGE) return null;
  const lower = (message || '').toLowerCase();
  if (!lower.trim()) return null;
  const ai = ['ai api returned', 'do ai request', 'ai grep', 'ai verdict', 'ai report', 'ai client', 'ai base url', 'ai response', 'api.ai.sbt', 'rate_limit', 'admission_queue']
    .some((part) => lower.includes(part));
  if (ai) {
    if (lower.includes('429') || lower.includes('rate_limit') || lower.includes('too many requests') || lower.includes('admission_queue')) {
      return { source: 'AI HUB', hint: 'AI HUB ограничил запросы: лимит или очередь переполнена.' };
    }
    if (lower.includes('deadline exceeded') || lower.includes('timeout')) {
      return { source: 'AI HUB', hint: 'AI HUB не ответил за отведённое время.' };
    }
    return { source: 'AI HUB', hint: 'Ошибка на стороне AI HUB.' };
  }
  if (lower.includes('cve patch')) return { source: 'Сервис патчей', hint: 'Не удалось получить патч уязвимости.' };
  if (lower.includes('git clone') || lower.includes('git checkout') || lower.includes('repository url')) {
    if (lower.includes('deadline exceeded') || lower.includes('timeout')) {
      return { source: 'Git', hint: 'Репозиторий не скачался за отведённое время.' };
    }
    return { source: 'Git', hint: 'Не удалось получить репозиторий.' };
  }
  if (lower.includes('deadcode')) return { source: 'CVE Patch Analyzer', hint: 'В анализе не найден инструмент deadcode.' };
  return { source: 'CVE Patch Analyzer', hint: 'Ошибка на стороне CVE Patch Analyzer.' };
}

function taskBlame(task) {
  if (!task?.error_msg) return null;
  if (task.error_source) return { source: task.error_source, hint: task.error_hint || '' };
  return blameError(task.error_msg);
}

function ErrorDetails({ task }) {
  const blame = taskBlame(task);
  return (
    <div style={{ textAlign: 'left' }}>
      {task.stop_stage && (
        <div style={{ textAlign: 'center', marginBottom: '1.25rem', fontSize: '1.15rem', fontWeight: '700', lineHeight: '1.55', color: theme.error.text }}>{task.stop_stage}</div>
      )}
      {blame && (
        <div style={{ textAlign: 'center', marginBottom: '1.25rem' }}>
          <div style={{ fontSize: '0.78rem', fontWeight: '800', letterSpacing: '0.06em', textTransform: 'uppercase', color: theme.error.text, opacity: 0.8 }}>Виноват</div>
          <div style={{ marginTop: '0.35rem', fontSize: '1.55rem', fontWeight: '800', color: theme.error.text }}>{blame.source}</div>
          {blame.hint && <div style={{ marginTop: '0.45rem', fontSize: '1.05rem', fontWeight: '600', color: theme.error.text }}>{blame.hint}</div>}
        </div>
      )}
      <div style={{ fontSize: '0.78rem', fontWeight: '800', letterSpacing: '0.05em', textTransform: 'uppercase', color: theme.textMuted, marginBottom: '0.4rem' }}>Подробности</div>
      <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontFamily: 'monospace', fontSize: '0.92rem', lineHeight: 1.55, fontWeight: '500', color: theme.error.text }}>{task.error_msg}</pre>
    </div>
  );
}

const quietLinkStyle = {
  display: 'inline-flex',
  alignItems: 'center',
  justifyContent: 'center',
  padding: '0.45rem 0.85rem',
  borderRadius: '0.65rem',
  border: `1px solid ${theme.primary}`,
  background: '#FFFFFF',
  color: theme.primary,
  fontSize: '0.9rem',
  fontWeight: '700',
  lineHeight: 1.2,
  textDecoration: 'none',
  whiteSpace: 'nowrap'
};

function paintQuietLink(node, active) {
  node.style.backgroundColor = active ? theme.primary : '#fff';
  node.style.color = active ? '#fff' : theme.primary;
}

function SwaggerButton() {
  return (
    <a
      href="/api/v1/analysis/docs/"
      target="_blank"
      rel="noreferrer"
      style={quietLinkStyle}
      onMouseEnter={e => paintQuietLink(e.currentTarget, true)}
      onMouseLeave={e => paintQuietLink(e.currentTarget, false)}
    >
      Swagger UI
    </a>
  );
}

function StarRow({ value, onPick, size = 22 }) {
  return (
    <span style={{ display: 'inline-flex', gap: '0.12rem', alignItems: 'center' }}>
      {[1, 2, 3, 4, 5].map((n) => {
        const mark = <span style={{ color: n <= (value || 0) ? '#F59E0B' : '#CBD5E1', fontSize: size, lineHeight: 1 }}>★</span>;
        if (!onPick) return <span key={n}>{mark}</span>;
        return (
          <button
            key={n}
            type="button"
            aria-label={`${n} из 5`}
            onClick={() => onPick(value === n ? 0 : n)}
            style={{ border: 'none', background: 'transparent', padding: 0, cursor: 'pointer', lineHeight: 1 }}
          >
            {mark}
          </button>
        );
      })}
    </span>
  );
}

function formatAverage(value) {
  if (value == null || value === '') return '—';
  const n = Number(value);
  if (!Number.isFinite(n)) return '—';
  const rounded = Math.round(n * 10) / 10;
  return Number.isInteger(rounded) ? String(rounded) : rounded.toFixed(1);
}

function displayGoVersion(raw) {
  const value = String(raw || '').trim();
  if (!value) return 'не выбрана';
  return value.startsWith('go1.') ? value.slice(2) : value;
}

function savedGoVersions(task) {
  if (!task || String(task.package_name || '').toLowerCase() !== 'stdlib') return '';
  const modules = task.modules || [];
  if (modules.length === 0) return '';
  const rows = modules.map((mod) => ({
    path: mod.go_mod_path || 'go.mod',
    version: displayGoVersion(mod.go_version)
  }));
  const unique = [...new Set(rows.map((row) => row.version))];
  if (rows.length === 1 || unique.length === 1) return unique[0];
  return rows.map((row) => `${row.path}: ${row.version}`).join('\n');
}

function diffLines(text) {
  const lines = String(text || '').replace(/\r\n/g, '\n').split('\n');
  if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();
  return lines;
}

function diffLineStyle(line) {
  if (line.startsWith('@@')) return { background: '#EFF6FF', color: '#1D4ED8' };
  if (line.startsWith('+++') || line.startsWith('---') || line.startsWith('diff ') || line.startsWith('index ')) {
    return { background: 'transparent', color: theme.textMuted };
  }
  if (line.startsWith('+')) return { background: theme.success.bg, color: theme.success.text };
  if (line.startsWith('-')) return { background: theme.error.bg, color: theme.error.text };
  return { background: 'transparent', color: theme.textMain };
}

export default function ApplicabilityAnalysis() {
  const location = useLocation();
  const { taskId } = useParams();

  const [formData, setFormData] = useState(() => {
    const storedData = sessionStorage.getItem('retry_analysis_data');
    if (storedData) {
      try {
        const parsed = JSON.parse(storedData);
        sessionStorage.removeItem('retry_analysis_data');
        return parsed;
      } catch (e) {
        console.error('Failed to parse retry data', e);
        sessionStorage.removeItem('retry_analysis_data');
      }
    }
    return { url: '', branch: '', cveId: '', packageName: '' };
  });

  const [currentTask, setCurrentTask] = useState(null);
  const [copiedVerdict, setCopiedVerdict] = useState(false);
  const [patchOpen, setPatchOpen] = useState(false);
  const [patchFile, setPatchFile] = useState(0);
  const [copiedPatch, setCopiedPatch] = useState(false);
  const [createError, setCreateError] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [taskList, setTaskList] = useState([]);
  const [totalTasks, setTotalTasks] = useState(0);
  const [searchDraft, setSearchDraft] = useState(emptySearch);
  const [appliedSearch, setAppliedSearch] = useState(emptySearch);
  const [searchSeq, setSearchSeq] = useState(0);
  const [listError, setListError] = useState('');
  const [reviewDraft, setReviewDraft] = useState({ rating: 0, text: '' });
  const [reviewError, setReviewError] = useState('');
  const [reviewSaving, setReviewSaving] = useState(false);
  const reviewSeed = useRef('');
  const [reviewPage, setReviewPage] = useState(1);
  const [reviewItems, setReviewItems] = useState([]);
  const [reviewTotal, setReviewTotal] = useState(0);
  const [reviewAverage, setReviewAverage] = useState(null);
  const [reviewRated, setReviewRated] = useState(0);
  const [reviewListError, setReviewListError] = useState('');
  const itemsPerPage = 10;

  const [selectedModuleIndex, setSelectedModuleIndex] = useState(0);
  const [selectedModel, setSelectedModel] = useState(readLastModel);
  const [currentGo, setCurrentGo] = useState(undefined);
  const [stopping, setStopping] = useState(false);
  const [stopError, setStopError] = useState('');

  useEffect(() => {
    setPatchOpen(false);
    setPatchFile(0);
    setCopiedPatch(false);
  }, [taskId]);

  const isReviewsView = location.pathname.includes('/reviews');
  const isListView = !isReviewsView && location.pathname.includes('/list');
  const isDetailView = !!taskId && !isListView && !isReviewsView;

  useEffect(() => {
    if (isDetailView || isListView || isReviewsView) return undefined;
    let cancelled = false;
    apiService.getDefaultModel()
      .then((model) => {
        if (!cancelled) setSelectedModel((current) => current || model);
      })
      .catch((err) => console.error('Error loading default model:', err));
    apiService.getCurrentGo()
      .then((version) => {
        if (!cancelled) setCurrentGo(version);
      })
      .catch((err) => console.error('Error loading Go version:', err));
    return () => { cancelled = true; };
  }, [isDetailView, isListView, isReviewsView]);

  useEffect(() => {
    if (isListView) {
      let cancelled = false;
      const loadList = async () => {
        try {
          const data = await apiService.getTasks(
            itemsPerPage,
            (currentPage - 1) * itemsPerPage,
            searchParams(appliedSearch)
          );
          if (cancelled) return;
          setTaskList(data.list || []);
          setTotalTasks(data.total || 0);
          setListError('');
        } catch (err) {
          if (!cancelled) setListError(err.message || 'Не удалось загрузить список');
        }
      };
      loadList();
      return () => { cancelled = true; };
    }
    return undefined;
  }, [isListView, currentPage, appliedSearch, searchSeq]);

  useEffect(() => {
    if (isDetailView && taskId) {
      const loadDetails = async () => {
        try {
          const data = await apiService.getTaskDetails(taskId);
          setCurrentTask(data);

          if (selectedModuleIndex >= (data.modules?.length || 0)) {
            setSelectedModuleIndex(0);
          }
        } catch (err) {
          console.error('Error loading details:', err);
        }
      };

      loadDetails();
      const interval = setInterval(loadDetails, 2000);
      return () => clearInterval(interval);
    }
  }, [isDetailView, taskId]);

  useEffect(() => {
    if (!currentTask || currentTask.id !== taskId) return;
    if (reviewSeed.current === currentTask.id) return;
    reviewSeed.current = currentTask.id;
    setReviewDraft({ rating: currentTask.rating || 0, text: currentTask.review || '' });
    setReviewError('');
  }, [currentTask, taskId]);

  useEffect(() => {
    if (!isReviewsView) return undefined;
    let cancelled = false;
    const loadReviews = async () => {
      try {
        const data = await apiService.getReviews(itemsPerPage, (reviewPage - 1) * itemsPerPage);
        if (cancelled) return;
        setReviewItems(data.items || []);
        setReviewTotal(data.total || 0);
        setReviewAverage(data.average);
        setReviewRated(data.rated || 0);
        setReviewListError('');
      } catch (err) {
        if (!cancelled) setReviewListError(err.message || 'Не удалось загрузить отзывы');
      }
    };
    loadReviews();
    return () => { cancelled = true; };
  }, [isReviewsView, reviewPage]);

  const handleSaveReview = async () => {
    if (!currentTask) return;
    setReviewSaving(true);
    setReviewError('');
    try {
      const saved = await apiService.saveReview(currentTask.id, {
        rating: reviewDraft.rating || null,
        review: reviewDraft.text
      });
      setCurrentTask((task) => (task ? { ...task, rating: saved.rating, review: saved.review || '' } : task));
      setReviewDraft({ rating: saved.rating || 0, text: saved.review || '' });
    } catch (err) {
      setReviewError(err.message || 'Не удалось сохранить отзыв');
    } finally {
      setReviewSaving(false);
    }
  };

  const handleClearReview = async () => {
    if (!currentTask) return;
    setReviewSaving(true);
    setReviewError('');
    try {
      const saved = await apiService.saveReview(currentTask.id, { rating: null, review: '' });
      setCurrentTask((task) => (task ? { ...task, rating: saved.rating, review: saved.review || '' } : task));
      setReviewDraft({ rating: 0, text: '' });
    } catch (err) {
      setReviewError(err.message || 'Не удалось убрать отзыв');
    } finally {
      setReviewSaving(false);
    }
  };

  const handleStartAnalysis = async () => {
    if (!formData.url || !formData.branch || !formData.cveId || !formData.packageName) return;

    setCreateError('');

    try {
      const result = await apiService.createTask({ ...formData, model: selectedModel });
      rememberModel(selectedModel);
      window.location.href = `/analysis/${result.id}`;
    } catch (err) {
      setCreateError(err.message || 'Произошла неизвестная ошибка при создании задачи');
    }
  };

  const handleClearForm = () => {
    setFormData({ url: '', branch: '', cveId: '', packageName: '' });
    setCreateError('');
  };

  const handleStopAnalysis = async () => {
    if (!currentTask || stopping) return;
    if (!window.confirm('Остановить анализ?')) return;
    setStopping(true);
    setStopError('');
    try {
      await apiService.stopTask(currentTask.id);
      const data = await apiService.getTaskDetails(currentTask.id);
      setCurrentTask(data);
    } catch (err) {
      setStopError(err.message || 'Не удалось остановить анализ');
    } finally {
      setStopping(false);
    }
  };

  const handleRetryAnalysis = () => {
    if (!currentTask) return;
    const retryData = {
      url: currentTask.component_url,
      branch: currentTask.branch,
      cveId: currentTask.cve_id,
      packageName: currentTask.package_name
    };
    sessionStorage.setItem('retry_analysis_data', JSON.stringify(retryData));
    window.location.href = '/analysis';
  };

  const copyText = (value, onDone) => {
    const textArea = document.createElement('textarea');
    textArea.value = value;
    textArea.setAttribute('readonly', '');
    textArea.style.position = 'fixed';
    textArea.style.top = '0';
    textArea.style.left = '0';
    textArea.style.opacity = '0';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    textArea.setSelectionRange(0, textArea.value.length);
    let ok = false;
    try {
      ok = document.execCommand('copy');
    } catch (err) {
      console.error('Failed to copy:', err);
    }
    document.body.removeChild(textArea);
    if (ok) {
      onDone();
      return;
    }
    const write = navigator.clipboard?.writeText;
    if (!write) return;
    write.call(navigator.clipboard, value).then(onDone).catch((err) => console.error('Failed to copy:', err));
  };

  const handleCopyVerdict = async () => {
    const activeModule = currentTask?.modules?.[selectedModuleIndex];
    if (!activeModule?.verdict) return;

    copyText(activeModule.verdict, () => setCopiedVerdict(true));
  };

  const handleCopyPatch = () => {
    const files = Array.isArray(currentTask?.patch_files) ? currentTask.patch_files : [];
    const file = files[Math.min(patchFile, files.length - 1)];
    if (!file?.patch) return;
    copyText(file.patch, () => setCopiedPatch(true));
  };

  const renderStatusBadge = (status) => {
    const labels = { PENDING: 'В очереди', RUNNING: 'В работе', COMPLETED: 'Завершен', FAILED: 'Ошибка' };
    let colors;
    if (status === 'FAILED') colors = theme.error;
    else if (status === 'COMPLETED') colors = theme.success;
    else if (status === 'RUNNING') colors = theme.running;
    else colors = theme.pending;

    return <span style={pillStyle(colors)}>{labels[status] || status}</span>;
  };

  const renderApplicabilityBadge = (value, scope = 'task') => {
    const view = applicabilityView(value, scope);
    if (!view) return null;
    return (
      <span title={view.hint} style={pillStyle(view.colors)}>
        <span style={{ width: '0.45rem', height: '0.45rem', borderRadius: '50%', backgroundColor: view.colors.accent, flexShrink: 0 }} />
        {view.label}
      </span>
    );
  };

  const renderDuration = (ms) => {
    const text = formatDuration(ms);
    if (!text) return null;
    return (
      <span title="Сколько шёл анализ, без ожидания в очереди" style={pillStyle({ bg: '#FFFFFF', text: theme.textMuted, border: theme.border })}>
        <ClockIcon />
        {text}
      </span>
    );
  };

  const formatDateTime = (iso) => {
    if (!iso) return '';
    return new Date(iso).toLocaleString('ru-RU', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false });
  };

  const activeModule = currentTask?.modules?.[selectedModuleIndex];

  if (isReviewsView) {
    const totalPages = Math.ceil(reviewTotal / itemsPerPage) || 1;
    return (
      <div style={fullPageStyle}>
        <div style={boardContainerStyle}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem', flexWrap: 'wrap', gap: '1.5rem' }}>
            <div>
              <h1 style={{ margin: 0, fontSize: '2.25rem', fontWeight: '800', color: theme.textMain }}>Отзывы</h1>
              <p style={{ margin: '0.5rem 0 0', color: theme.textMuted, fontSize: '1.1rem' }}>
                Средняя оценка {formatAverage(reviewAverage)}
                {reviewRated ? ` · ${reviewRated} со звёздами` : ''}
              </p>
            </div>
            <div style={navBtnGroupStyle}>
              <button onClick={() => window.location.href = '/analysis/list'} style={listNavBtnStyle} onMouseEnter={e => { e.currentTarget.style.backgroundColor = theme.primary; e.currentTarget.style.color = '#fff'; }} onMouseLeave={e => { e.currentTarget.style.backgroundColor = '#fff'; e.currentTarget.style.color = theme.primary; }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="8" y1="6" x2="21" y2="6" /><line x1="8" y1="12" x2="21" y2="12" /><line x1="8" y1="18" x2="21" y2="18" /><line x1="3" y1="6" x2="3.01" y2="6" /><line x1="3" y1="12" x2="3.01" y2="12" /><line x1="3" y1="18" x2="3.01" y2="18" /></svg>
                Список анализов
              </button>
              <button onClick={() => window.location.href = '/analysis'} style={backBtnStyle} onMouseEnter={e => { e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.5)'; e.currentTarget.style.borderColor = theme.primary; e.currentTarget.style.color = theme.primary; }} onMouseLeave={e => { e.currentTarget.style.backgroundColor = 'transparent'; e.currentTarget.style.borderColor = theme.borderDark; e.currentTarget.style.color = theme.textMuted; }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="16" /><line x1="8" y1="12" x2="16" y2="12" /></svg>
                Новый анализ
              </button>
            </div>
          </div>

          {reviewListError && (
            <div style={{ ...innerCardStyle, marginBottom: '1.5rem', color: theme.error.text, backgroundColor: theme.error.bg, borderColor: theme.error.border }}>
              {reviewListError}
            </div>
          )}

          {reviewItems.length === 0 ? (
            <div style={{ ...innerCardStyle, textAlign: 'center', padding: '5rem', color: theme.textMuted }}>Отзывов пока нет</div>
          ) : (
            <>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                {reviewItems.map((item) => (
                  <div
                    key={item.id}
                    onClick={() => window.location.href = `/analysis/${item.id}`}
                    style={{ ...innerCardStyle, cursor: 'pointer', transition: 'all 0.2s' }}
                    onMouseEnter={e => { e.currentTarget.style.borderColor = theme.primary; }}
                    onMouseLeave={e => { e.currentTarget.style.borderColor = 'rgba(203, 213, 225, 0.6)'; }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.75rem', flexWrap: 'wrap' }}>
                      {item.rating ? <StarRow value={item.rating} size={22} /> : <span style={{ color: theme.textMuted, fontWeight: '700' }}>Без звёзд</span>}
                      <span style={{ fontWeight: '800', color: theme.textMain }}>{item.cve_id}</span>
                      <span style={{ color: theme.textMuted, fontSize: '0.9rem' }}>{formatDateTime(item.created_at)}</span>
                    </div>
                    {item.review && (
                      <p style={{ margin: '0 0 0.85rem', color: theme.textMain, fontSize: '1.05rem', lineHeight: 1.55, whiteSpace: 'pre-wrap' }}>{item.review}</p>
                    )}
                    <div style={{ color: theme.textMuted, fontSize: '0.95rem', wordBreak: 'break-all' }}>
                      {item.component_url} · {item.branch} · {item.package_name}
                    </div>
                  </div>
                ))}
              </div>
              {totalPages > 1 && (
                <div style={{ display: 'flex', justifyContent: 'center', gap: '0.5rem', marginTop: '2.5rem' }}>
                  <button disabled={reviewPage === 1} onClick={() => setReviewPage(p => p - 1)} style={{ width: '44px', height: '44px', borderRadius: '0.75rem', border: 'none', backgroundColor: 'rgba(255,255,255,0.6)', color: theme.textMuted, fontWeight: '700', cursor: reviewPage === 1 ? 'default' : 'pointer', opacity: reviewPage === 1 ? 0.5 : 1 }}>←</button>
                  <span style={{ display: 'flex', alignItems: 'center', color: theme.textMuted, fontWeight: '600' }}>Страница {reviewPage} из {totalPages}</span>
                  <button disabled={reviewPage === totalPages} onClick={() => setReviewPage(p => p + 1)} style={{ width: '44px', height: '44px', borderRadius: '0.75rem', border: 'none', backgroundColor: 'rgba(255,255,255,0.6)', color: theme.textMuted, fontWeight: '700', cursor: reviewPage === totalPages ? 'default' : 'pointer', opacity: reviewPage === totalPages ? 0.5 : 1 }}>→</button>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    );
  }

  if (isDetailView) {
    if (!currentTask) return <div style={fullPageStyle}><div style={boardContainerStyle}><div style={{ textAlign: 'center', padding: '6rem' }}><h2>Загрузка...</h2></div></div></div>;

    const isError = currentTask.status === 'FAILED';
    const isStopped = isError && currentTask.error_msg === STOPPED_MESSAGE;
    const isDone = currentTask.status === 'COMPLETED';
    const isRunning = currentTask.status === 'RUNNING';
    const isPending = currentTask.status === 'PENDING';
    const taskResult = applicabilityView(currentTask.applicability);
    const moduleResult = applicabilityView(activeModule?.applicability, 'module');
    const durationText = formatDuration(currentTask.duration_ms);
    const terminal = isDone || isError;
    const aiKnown = terminal || currentTask.ai_calls > 0 || currentTask.ai_min_ms != null || currentTask.ai_max_ms != null;
    const cloneText = currentTask.clone_ms == null ? '—' : (formatDuration(currentTask.clone_ms) || '—');
    const goModText = currentTask.go_mod_count == null ? '—' : String(currentTask.go_mod_count);
    const aiCallsText = aiKnown ? String(currentTask.ai_calls ?? 0) : '—';
    const aiFastText = currentTask.ai_min_ms == null ? '—' : (formatDuration(currentTask.ai_min_ms) || '—');
    const aiSlowText = currentTask.ai_max_ms == null ? '—' : (formatDuration(currentTask.ai_max_ms) || '—');
    const savedGo = isDone ? savedGoVersions(currentTask) : '';

    let statusTheme;
    if (isError) statusTheme = theme.error;
    else if (isDone) statusTheme = moduleResult?.colors || taskResult?.colors || theme.success;
    else if (isRunning || isPending) statusTheme = theme.running;
    else statusTheme = theme.pending;

    const resultHint = isStopped
      ? 'Анализ остановлен до вывода о применимости'
      : isError
        ? 'Задача завершилась с ошибкой, поэтому результат неопределенный'
        : taskResult?.hint;

    return (
      <div style={fullPageStyle}>
        <div style={boardContainerStyle}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '3rem', flexWrap: 'wrap', gap: '1.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem', minWidth: 0, flex: '1 1 0%' }}>
              <div style={{ width: '64px', height: '64px', borderRadius: '50%', backgroundColor: theme.primary, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff', boxShadow: '0 8px 16px -4px rgba(37, 99, 235, 0.25)', flexShrink: 0 }}>
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
              </div>
              <div style={{ minWidth: 0 }}>
                <h1 style={{ margin: 0, fontSize: '2.25rem', fontWeight: '800', color: theme.textMain }}>Детали анализа</h1>
                <p style={{ margin: '0.5rem 0 0', color: theme.textMuted, fontSize: '1.1rem', fontVariantNumeric: 'tabular-nums' }}>
                  ID: {currentTask.id.slice(0, 8)}... • {formatDateTime(currentTask.created_at)}
                  {showDuration(currentTask.status, currentTask.duration_ms) ? ` • ${durationText}` : ''}
                </p>
              </div>
            </div>
            <div style={{ ...navBtnGroupStyle, marginLeft: 'auto' }}>
              <button onClick={() => window.location.href = '/analysis/list'} style={listNavBtnStyle} onMouseEnter={e => { e.currentTarget.style.backgroundColor = theme.primary; e.currentTarget.style.color = '#fff'; }} onMouseLeave={e => { e.currentTarget.style.backgroundColor = '#fff'; e.currentTarget.style.color = theme.primary; }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="8" y1="6" x2="21" y2="6" /><line x1="8" y1="12" x2="21" y2="12" /><line x1="8" y1="18" x2="21" y2="18" /><line x1="3" y1="6" x2="3.01" y2="6" /><line x1="3" y1="12" x2="3.01" y2="12" /><line x1="3" y1="18" x2="3.01" y2="18" /></svg>
                Список анализов
              </button>
              <button onClick={() => window.location.href = '/'} style={backBtnStyle} onMouseEnter={e => { e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.5)'; e.currentTarget.style.borderColor = theme.primary; e.currentTarget.style.color = theme.primary; }} onMouseLeave={e => { e.currentTarget.style.backgroundColor = 'transparent'; e.currentTarget.style.borderColor = theme.borderDark; e.currentTarget.style.color = theme.textMuted; }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" /><polyline points="9 22 9 12 15 12 15 22" /></svg>
                Вернуться в CVE Patch Analyzer
              </button>
            </div>
          </div>

          <div style={{ ...innerCardStyle, marginBottom: '2.5rem' }}>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginBottom: '1.25rem', flexWrap: 'wrap' }}>
              {(isRunning || isPending) && (
                <button
                  onClick={handleStopAnalysis}
                  disabled={stopping}
                  style={{
                    display: 'inline-flex', alignItems: 'center', gap: '0.5rem',
                    padding: '0.6rem 1.25rem', borderRadius: '0.75rem',
                    border: `1px solid ${theme.error.border}`, background: theme.error.bg,
                    color: theme.error.text, fontSize: '0.9rem', fontWeight: '700',
                    cursor: stopping ? 'default' : 'pointer', transition: 'all 0.2s',
                    opacity: stopping ? 0.7 : 1
                  }}
                >
                  {stopping ? 'Останавливаем...' : 'Остановить анализ'}
                </button>
              )}
              <button
                onClick={handleRetryAnalysis}
                style={{
                  display: 'inline-flex', alignItems: 'center', gap: '0.5rem',
                  padding: '0.6rem 1.25rem', borderRadius: '0.75rem',
                  border: `1px solid ${theme.border}`, background: '#ffffff',
                  color: theme.primary, fontSize: '0.9rem', fontWeight: '700',
                  cursor: 'pointer', transition: 'all 0.2s',
                  boxShadow: '0 2px 4px rgba(0,0,0,0.05)'
                }}
                onMouseEnter={e => { e.currentTarget.style.backgroundColor = theme.primaryLight; e.currentTarget.style.borderColor = theme.primary; }}
                onMouseLeave={e => { e.currentTarget.style.backgroundColor = '#ffffff'; e.currentTarget.style.borderColor = theme.border; }}
              >
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M23 4v6h-6" /><path d="M1 20v-6h6" /><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" /></svg>
                Повторить анализ
              </button>
            </div>
            {stopError && (
              <p style={{ margin: '-0.5rem 0 1rem', textAlign: 'right', color: theme.error.text, fontWeight: '600' }}>{stopError}</p>
            )}

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))', gap: '0.75rem', marginBottom: '1.5rem' }}>
              <div style={{ background: '#fff', border: `1px solid ${theme.border}`, borderRadius: '0.85rem', padding: '0.9rem 1rem' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: '700', letterSpacing: '0.04em', textTransform: 'uppercase', color: theme.textMuted, marginBottom: '0.5rem' }}>Статус</div>
                {renderStatusBadge(currentTask.status)}
              </div>
              <div style={{ background: '#fff', border: `1px solid ${taskResult ? taskResult.colors.border : theme.border}`, borderRadius: '0.85rem', padding: '0.9rem 1rem' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: '700', letterSpacing: '0.04em', textTransform: 'uppercase', color: theme.textMuted, marginBottom: '0.5rem' }}>Применимость</div>
                {taskResult ? renderApplicabilityBadge(currentTask.applicability) : (
                  <span style={{ color: theme.textMuted, fontWeight: '600' }}>Появится после завершения</span>
                )}
              </div>
              <div style={{ background: '#fff', border: `1px solid ${theme.border}`, borderRadius: '0.85rem', padding: '0.9rem 1rem' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: '700', letterSpacing: '0.04em', textTransform: 'uppercase', color: theme.textMuted, marginBottom: '0.5rem' }}>Время</div>
                {showDuration(currentTask.status, currentTask.duration_ms) ? renderDuration(currentTask.duration_ms) : (
                  <span style={{ color: theme.textMuted, fontWeight: '600' }}>—</span>
                )}
              </div>
              <div style={{ background: '#fff', border: `1px solid ${theme.border}`, borderRadius: '0.85rem', padding: '0.9rem 1rem' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: '700', letterSpacing: '0.04em', textTransform: 'uppercase', color: theme.textMuted, marginBottom: '0.5rem' }}>Клонирование</div>
                <b style={{ color: theme.textMain, fontSize: '1.05rem' }}>{cloneText}</b>
              </div>
              <div style={{ background: '#fff', border: `1px solid ${theme.border}`, borderRadius: '0.85rem', padding: '0.9rem 1rem' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: '700', letterSpacing: '0.04em', textTransform: 'uppercase', color: theme.textMuted, marginBottom: '0.5rem' }}>go.mod</div>
                <b style={{ color: theme.textMain, fontSize: '1.05rem' }}>{goModText}</b>
              </div>
              <div style={{ background: '#fff', border: `1px solid ${theme.border}`, borderRadius: '0.85rem', padding: '0.9rem 1rem' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: '700', letterSpacing: '0.04em', textTransform: 'uppercase', color: theme.textMuted, marginBottom: '0.5rem' }}>Обращений к ИИ</div>
                <b style={{ color: theme.textMain, fontSize: '1.05rem' }}>{aiCallsText}</b>
              </div>
              <div style={{ background: '#fff', border: `1px solid ${theme.border}`, borderRadius: '0.85rem', padding: '0.9rem 1rem' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: '700', letterSpacing: '0.04em', textTransform: 'uppercase', color: theme.textMuted, marginBottom: '0.5rem' }}>Самый быстрый ответ от ИИ</div>
                <b style={{ color: theme.textMain, fontSize: '1.05rem' }}>{aiFastText}</b>
              </div>
              <div style={{ background: '#fff', border: `1px solid ${theme.border}`, borderRadius: '0.85rem', padding: '0.9rem 1rem' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: '700', letterSpacing: '0.04em', textTransform: 'uppercase', color: theme.textMuted, marginBottom: '0.5rem' }}>Самый долгий ответ от ИИ</div>
                <b style={{ color: theme.textMain, fontSize: '1.05rem' }}>{aiSlowText}</b>
              </div>
            </div>

            {resultHint && (
              <p style={{ margin: '0 0 1.25rem', color: taskResult?.colors.text || theme.textMuted, fontSize: '0.95rem', fontWeight: '600' }}>{resultHint}</p>
            )}

            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              <div style={{ width: '100%' }}>
                <span style={{ color: theme.textMuted, fontWeight: '600', display: 'block', marginBottom: '0.4rem', fontSize: '0.8rem', textTransform: 'uppercase' }}>Компонент</span>
                <b style={{ wordBreak: 'break-all', color: theme.primary, fontSize: '1.1rem', lineHeight: '1.5' }}>
                  {currentTask.component_url}
                </b>
              </div>

              <div style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                gap: '1.5rem',
                borderTop: `1px solid ${theme.border}`,
                paddingTop: '1.25rem'
              }}>
                <div>
                  <span style={{ color: theme.textMuted, fontWeight: '600', display: 'block', marginBottom: '0.4rem', fontSize: '0.8rem', textTransform: 'uppercase' }}>Ветка</span>
                  <b style={{ color: theme.primary }}>{currentTask.branch}</b>
                </div>
                <div>
                  <span style={{ color: theme.textMuted, fontWeight: '600', display: 'block', marginBottom: '0.4rem', fontSize: '0.8rem', textTransform: 'uppercase' }}>CVE ID</span>
                  <b style={{ color: theme.primary }}>{currentTask.cve_id}</b>
                </div>
                <div>
                  <span style={{ color: theme.textMuted, fontWeight: '600', display: 'block', marginBottom: '0.4rem', fontSize: '0.8rem', textTransform: 'uppercase' }}>Пакет</span>
                  <b style={{ wordBreak: 'break-all', color: theme.primary }}>{currentTask.package_name}</b>
                </div>
                {savedGo && (
                  <div>
                    <span style={{ color: theme.textMuted, fontWeight: '600', display: 'block', marginBottom: '0.4rem', fontSize: '0.8rem', textTransform: 'uppercase' }}>Go</span>
                    <b style={{ wordBreak: 'break-all', whiteSpace: 'pre-line', color: theme.primary }}>{savedGo}</b>
                  </div>
                )}
                <div>
                  <span style={{ color: theme.textMuted, fontWeight: '600', display: 'block', marginBottom: '0.4rem', fontSize: '0.8rem', textTransform: 'uppercase' }}>Модель</span>
                  <b style={{ wordBreak: 'break-all', color: theme.primary }}>{currentTask.model || '—'}</b>
                </div>
              </div>
            </div>
          </div>

          <div style={{ ...innerCardStyle, marginBottom: '2.5rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
              <div>
                <h2 style={{ margin: 0, fontSize: '1.2rem', fontWeight: '800', color: theme.textMain }}>Оценка</h2>
                <p style={{ margin: '0.35rem 0 0', color: theme.textMuted, fontSize: '0.95rem' }}>5 — вердикт верный, 1 — неверный. Можно ничего не ставить.</p>
              </div>
              <StarRow value={reviewDraft.rating} onPick={(n) => setReviewDraft({ ...reviewDraft, rating: n })} size={32} />
            </div>
            <textarea
              value={reviewDraft.text}
              onChange={(e) => setReviewDraft({ ...reviewDraft, text: e.target.value })}
              placeholder="Почему такая оценка. Можно оставить пустым."
              rows={4}
              style={{ width: '100%', boxSizing: 'border-box', border: `1px solid ${theme.border}`, borderRadius: '0.75rem', padding: '0.9rem 1rem', fontSize: '1rem', fontFamily: 'inherit', color: theme.textMain, background: 'rgba(255,255,255,0.85)', resize: 'vertical' }}
            />
            {reviewError && <p style={{ margin: '0.75rem 0 0', color: theme.error.text, fontWeight: '600' }}>{reviewError}</p>}
            <div style={{ display: 'flex', gap: '0.75rem', marginTop: '1rem', flexWrap: 'wrap' }}>
              <button type="button" onClick={handleSaveReview} disabled={reviewSaving} style={{ ...listNavBtnStyle, backgroundColor: theme.primary, color: '#fff', borderColor: theme.primary, opacity: reviewSaving ? 0.7 : 1, cursor: reviewSaving ? 'default' : 'pointer' }}>
                {reviewSaving ? 'Сохраняем...' : 'Сохранить'}
              </button>
              {(currentTask.rating || currentTask.review) && (
                <button type="button" onClick={handleClearReview} disabled={reviewSaving} style={{ ...backBtnStyle, opacity: reviewSaving ? 0.7 : 1 }}>
                  Убрать
                </button>
              )}
            </div>
          </div>

          {isDone && currentTask.modules && currentTask.modules.length > 0 && (
            <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '2rem', flexWrap: 'wrap' }}>
              {currentTask.modules.map((mod, idx) => {
                const modView = applicabilityView(mod.applicability, 'module');
                const selected = selectedModuleIndex === idx;
                return (
                  <button
                    key={idx}
                    title={modView?.hint}
                    onClick={() => { setSelectedModuleIndex(idx); setCopiedVerdict(false); }}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '0.55rem',
                      padding: '0.6rem 1.25rem',
                      borderRadius: '0.75rem',
                      border: `1px solid ${selected ? theme.primary : theme.border}`,
                      background: selected ? theme.primary : '#ffffff',
                      color: selected ? '#ffffff' : theme.textMuted,
                      fontSize: '0.9rem',
                      fontWeight: '600',
                      cursor: 'pointer',
                      transition: 'all 0.2s ease',
                      boxShadow: selected ? '0 4px 12px rgba(37, 99, 235, 0.2)' : 'none'
                    }}
                    onMouseEnter={e => {
                      if (!selected) {
                        e.currentTarget.style.backgroundColor = theme.primaryLight;
                        e.currentTarget.style.borderColor = theme.primary;
                        e.currentTarget.style.color = theme.primary;
                      }
                    }}
                    onMouseLeave={e => {
                      if (!selected) {
                        e.currentTarget.style.backgroundColor = '#ffffff';
                        e.currentTarget.style.borderColor = theme.border;
                        e.currentTarget.style.color = theme.textMuted;
                      }
                    }}
                  >
                    {modView && (
                      <span style={{ width: '0.55rem', height: '0.55rem', borderRadius: '50%', backgroundColor: selected ? '#fff' : modView.colors.accent, boxShadow: selected ? 'none' : `0 0 0 3px ${modView.colors.bg}`, flexShrink: 0 }} />
                    )}
                    {mod.go_mod_path}
                  </button>
                );
              })}
            </div>
          )}

          <div style={{ marginBottom: '2.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1rem', marginBottom: '1.5rem', flexWrap: 'wrap' }}>
              <h2 style={{ fontSize: '1.35rem', fontWeight: '800', margin: 0, color: theme.textMain }}>Окончательный вердикт</h2>
              {isDone && moduleResult && renderApplicabilityBadge(activeModule.applicability, 'module')}
            </div>
            {(isRunning || isPending) ? (
              <div style={{ padding: '3rem', textAlign: 'center', color: theme.textMuted, fontWeight: '500', fontSize: '1.2rem', border: `2px dashed ${theme.border}`, borderRadius: '1rem', backgroundColor: 'rgba(255,255,255,0.4)' }}>Информация появится после завершения анализа</div>
            ) : isStopped ? (
              <div style={{ padding: '2.5rem 3rem', textAlign: 'center', color: theme.error.text, fontWeight: '700', fontSize: '1.3rem', lineHeight: '1.7', border: `1px solid ${theme.error.border}`, borderRadius: '1rem', backgroundColor: theme.error.bg, borderLeft: `8px solid ${theme.error.accent}` }}>
                {STOPPED_MESSAGE}
              </div>
            ) : isError ? (
              <div style={{ padding: '2rem 2.25rem', color: theme.error.text, fontWeight: '700', fontSize: '1.2rem', border: `1px solid ${theme.error.border}`, borderRadius: '1rem', backgroundColor: theme.error.bg, borderLeft: `8px solid ${theme.error.accent}` }}>
                <div style={{ textAlign: 'center', marginBottom: '1.25rem' }}>Анализ завершился с ошибкой</div>
                <ErrorDetails task={currentTask} />
              </div>
            ) : (
              <div style={{
                position: 'relative',
                padding: '2.5rem 10rem 2.5rem 3rem',
                fontSize: '1.3rem', lineHeight: '1.7', fontWeight: '700', color: statusTheme.text,
                backgroundColor: statusTheme.bg, borderRadius: '1rem',
                border: `1px solid ${statusTheme.border}`, borderLeft: `8px solid ${statusTheme.accent}`
              }}>
                <button
                  onClick={handleCopyVerdict}
                  style={{
                    position: 'absolute', top: '1.5rem', right: '1.5rem',
                    display: 'inline-flex', alignItems: 'center', gap: '0.5rem',
                    padding: '0.6rem 1rem', borderRadius: '0.5rem',
                    border: `1px solid ${theme.border}`, background: '#ffffff',
                    color: theme.textMuted, fontSize: '0.9rem', fontWeight: '600',
                    cursor: 'pointer', whiteSpace: 'nowrap'
                  }}
                  onMouseEnter={e => { e.currentTarget.style.color = theme.textMain; e.currentTarget.style.borderColor = theme.textMuted; }}
                  onMouseLeave={e => { e.currentTarget.style.color = theme.textMuted; e.currentTarget.style.borderColor = theme.border; }}
                >
                  {copiedVerdict ? (
                    <>
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#059669" strokeWidth="2.5"><polyline points="20 6 9 17 4 12" /></svg>
                      Скопировано
                    </>
                  ) : (
                    <>
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>
                      Копировать
                    </>
                  )}
                </button>
                {activeModule?.verdict || 'Вердикт отсутствует'}
              </div>
            )}
          </div>

          {!isPending && !isRunning && (() => {
            const patchFiles = Array.isArray(currentTask.patch_files) ? currentTask.patch_files : [];
            const safeIndex = patchFiles.length === 0 ? 0 : Math.min(patchFile, patchFiles.length - 1);
            const activePatch = patchFiles[safeIndex];
            const lines = diffLines(activePatch?.patch);
            return (
              <div style={{ marginBottom: '2.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1rem', marginBottom: patchOpen ? '1.25rem' : 0, flexWrap: 'wrap' }}>
                  <h2 style={{ fontSize: '1.35rem', fontWeight: '800', margin: 0, color: theme.textMain }}>Патч</h2>
                  <button
                    type="button"
                    onClick={() => { setPatchOpen((open) => !open); setCopiedPatch(false); }}
                    style={{
                      display: 'inline-flex', alignItems: 'center', gap: '0.5rem',
                      padding: '0.6rem 1.25rem', borderRadius: '0.75rem',
                      border: `1px solid ${theme.primary}`, background: patchOpen ? '#ffffff' : theme.primary,
                      color: patchOpen ? theme.primary : '#ffffff', fontSize: '0.95rem', fontWeight: '700',
                      cursor: 'pointer'
                    }}
                  >
                    {patchOpen ? 'Свернуть патч' : 'Показать патч'}
                  </button>
                </div>
                {patchOpen && (patchFiles.length === 0 ? (
                  <div style={{ padding: '2.5rem', textAlign: 'center', color: theme.textMuted, fontWeight: '600', border: `2px dashed ${theme.border}`, borderRadius: '1rem', backgroundColor: 'rgba(255,255,255,0.4)' }}>
                    Патч не найден
                  </div>
                ) : (
                  <div style={{ backgroundColor: 'rgba(255, 255, 255, 0.7)', borderRadius: '1rem', border: `1px solid rgba(203, 213, 225, 0.8)`, overflow: 'hidden' }}>
                    {patchFiles.length > 1 && (
                      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', padding: '1rem 1.25rem', borderBottom: `1px solid ${theme.border}`, backgroundColor: 'rgba(248, 250, 252, 0.8)' }}>
                        {patchFiles.map((file, idx) => {
                          const selected = idx === safeIndex;
                          return (
                            <button
                              key={`${file.path}-${idx}`}
                              type="button"
                              onClick={() => { setPatchFile(idx); setCopiedPatch(false); }}
                              style={{
                                maxWidth: '100%', textAlign: 'left', wordBreak: 'break-all',
                                padding: '0.45rem 0.8rem', borderRadius: '0.6rem',
                                border: `1px solid ${selected ? theme.primary : theme.border}`,
                                background: selected ? theme.primary : '#ffffff',
                                color: selected ? '#ffffff' : theme.textMain,
                                fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
                                fontSize: '0.82rem', fontWeight: '600', cursor: 'pointer'
                              }}
                            >
                              {file.path}
                            </button>
                          );
                        })}
                      </div>
                    )}
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem', padding: '1rem 1.25rem', borderBottom: `1px solid ${theme.border}`, flexWrap: 'wrap' }}>
                      <span style={{ wordBreak: 'break-all', fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace', fontSize: '0.92rem', fontWeight: '700', color: theme.textMain }}>{activePatch.path}</span>
                      <button
                        type="button"
                        onClick={handleCopyPatch}
                        style={{
                          display: 'inline-flex', alignItems: 'center', gap: '0.5rem', flexShrink: 0,
                          padding: '0.55rem 0.95rem', borderRadius: '0.5rem',
                          border: `1px solid ${theme.border}`, background: '#ffffff',
                          color: theme.textMuted, fontSize: '0.9rem', fontWeight: '600', cursor: 'pointer'
                        }}
                      >
                        {copiedPatch ? 'Скопировано' : 'Копировать'}
                      </button>
                    </div>
                    <div style={{ overflow: 'auto', maxHeight: '28rem', backgroundColor: '#F8FAFC' }}>
                      {lines.map((line, idx) => {
                        const look = diffLineStyle(line);
                        return (
                          <div key={idx} style={{ ...look, padding: '0 1rem', fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace', fontSize: '0.82rem', lineHeight: '1.55', whiteSpace: 'pre', minWidth: 'max-content' }}>
                            {line || ' '}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            );
          })()}

          <div>
            <h2 style={{ fontSize: '1.35rem', fontWeight: '800', marginBottom: '1.5rem', color: theme.textMain }}>Полный отчет</h2>
            {(isRunning || isPending) ? (
              <div style={{ padding: '3rem', textAlign: 'center', color: theme.textMuted, fontWeight: '500', border: `2px dashed ${theme.border}`, borderRadius: '1rem', backgroundColor: 'rgba(255,255,255,0.4)' }}>
                Отчет сформируется позже
              </div>
            ) : isStopped ? (
              <div style={{ padding: '3rem', textAlign: 'center', color: theme.textMuted, fontWeight: '500', border: `2px dashed ${theme.border}`, borderRadius: '1rem', backgroundColor: 'rgba(255,255,255,0.4)' }}>
                Отчет не сформирован: анализ остановлен до конца.
              </div>
            ) : isError ? (
              <div style={{ padding: '2rem 2.25rem', textAlign: 'left', color: theme.textMuted, fontWeight: '500', border: `2px dashed ${theme.border}`, borderRadius: '1rem', backgroundColor: 'rgba(255,255,255,0.4)' }}>
                <ErrorDetails task={currentTask} />
              </div>
            ) : (
              <div style={{ backgroundColor: 'rgba(255, 255, 255, 0.7)', borderRadius: '1rem', border: `1px solid rgba(203, 213, 225, 0.8)`, overflow: 'hidden' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', padding: '1.25rem 2rem', backgroundColor: 'rgba(219, 234, 254, 0.5)', borderBottom: `1px solid rgba(203, 213, 225, 0.6)`, flexWrap: 'wrap' }}>
                  <span style={{ color: theme.textMuted, fontSize: '0.95rem', fontWeight: '700' }}>report-{activeModule?.go_mod_path || currentTask.cve_id}.md</span>
                  <a href={apiService.downloadReportUrl(currentTask.id)} style={{ textDecoration: 'none' }}>
                    <button style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem', padding: '0.6rem 1.25rem', borderRadius: '0.5rem', border: `1px solid ${theme.border}`, background: '#ffffff', color: theme.textMain, fontSize: '0.9rem', fontWeight: '600', cursor: 'pointer' }} onMouseEnter={e => { e.currentTarget.style.backgroundColor = theme.primaryLight; }} onMouseLeave={e => { e.currentTarget.style.backgroundColor = '#ffffff'; }}>
                      Скачать .md
                    </button>
                  </a>
                </div>
                <pre style={{ padding: '2.5rem', fontSize: '1rem', overflow: 'auto', maxHeight: '500px', lineHeight: '1.8', fontFamily: 'monospace', whiteSpace: 'pre-wrap', color: theme.textMain, margin: 0, backgroundColor: 'rgba(248, 250, 252, 0.5)' }}>
                  {activeModule?.report_md || 'Отчет пуст'}
                </pre>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  if (isListView) {
    const totalPages = Math.ceil(totalTasks / itemsPerPage) || 1;
    const filtering = searchFilled(appliedSearch);
    const runSearch = (event) => {
      event.preventDefault();
      setAppliedSearch({
        url: searchDraft.url.trim(),
        branch: searchDraft.branch.trim(),
        cveId: searchDraft.cveId.trim(),
        packageName: searchDraft.packageName.trim(),
        result: searchDraft.result
      });
      setCurrentPage(1);
      setSearchSeq((n) => n + 1);
    };
    const resetSearch = () => {
      setSearchDraft(emptySearch);
      setAppliedSearch(emptySearch);
      setCurrentPage(1);
      setSearchSeq((n) => n + 1);
    };
    const searchField = (name, label, placeholder) => (
      <label style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem', minWidth: 0 }}>
        <span style={{ fontSize: '0.85rem', fontWeight: '700', color: theme.textMain }}>{label}</span>
        <input
          name={name}
          value={searchDraft[name]}
          placeholder={placeholder}
          onChange={(e) => setSearchDraft({ ...searchDraft, [name]: e.target.value })}
          style={{ border: `1px solid ${theme.border}`, borderRadius: '0.75rem', padding: '0.85rem 1rem', fontSize: '1rem', width: '100%', boxSizing: 'border-box', outline: 'none', backgroundColor: 'rgba(255,255,255,0.85)', color: theme.textMain }}
        />
      </label>
    );

    return (
      <div style={fullPageStyle}>
        <div style={boardContainerStyle}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '3rem', flexWrap: 'wrap', gap: '1.5rem' }}>
            <div>
              <h1 style={{ margin: 0, fontSize: '2.25rem', fontWeight: '800', color: theme.textMain }}>Список анализов</h1>
              <p style={{ margin: '0.5rem 0 0', color: theme.textMuted, fontSize: '1.1rem' }}>{filtering ? `Найдено ${totalTasks}` : `История проверок (${totalTasks} всего)`}</p>
            </div>
            <div style={navBtnGroupStyle}>
              <button onClick={() => window.location.href = '/analysis'} style={listNavBtnStyle} onMouseEnter={e => { e.currentTarget.style.backgroundColor = theme.primary; e.currentTarget.style.color = '#fff'; }} onMouseLeave={e => { e.currentTarget.style.backgroundColor = '#fff'; e.currentTarget.style.color = theme.primary; }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="16" /><line x1="8" y1="12" x2="16" y2="12" /></svg>
                Новый анализ
              </button>
              <button onClick={() => window.location.href = '/'} style={backBtnStyle} onMouseEnter={e => { e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.5)'; e.currentTarget.style.borderColor = theme.primary; e.currentTarget.style.color = theme.primary; }} onMouseLeave={e => { e.currentTarget.style.backgroundColor = 'transparent'; e.currentTarget.style.borderColor = theme.borderDark; e.currentTarget.style.color = theme.textMuted; }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" /><polyline points="9 22 9 12 15 12 15 22" /></svg>
                Вернуться в CVE Patch Analyzer
              </button>
            </div>
          </div>

          <form onSubmit={runSearch} style={{ ...innerCardStyle, marginBottom: '1.5rem', padding: '1.5rem' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.9rem', alignItems: 'end' }}>
              {searchField('url', 'Репозиторий', 'grpc-go или полный адрес')}
              {searchField('branch', 'Ветка', 'main')}
              {searchField('cveId', 'CVE или алиас', 'CVE-2025-22869')}
              {searchField('packageName', 'Пакет', 'root')}
              <label style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem', minWidth: 0 }}>
                <span style={{ fontSize: '0.85rem', fontWeight: '700', color: theme.textMain }}>Статус</span>
                <select
                  value={searchDraft.result}
                  onChange={(e) => setSearchDraft({ ...searchDraft, result: e.target.value })}
                  style={{ border: `1px solid ${theme.border}`, borderRadius: '0.75rem', padding: '0.85rem 1rem', fontSize: '1rem', width: '100%', boxSizing: 'border-box', outline: 'none', backgroundColor: 'rgba(255,255,255,0.85)', color: theme.textMain }}
                >
                  <option value="">Любой</option>
                  <option value="PENDING">В очереди</option>
                  <option value="RUNNING">В работе</option>
                  <option value="FAILED">Ошибка</option>
                  <option value="applicable">Применима</option>
                  <option value="not_applicable">Неприменима</option>
                  <option value="uncertain">Неопределенно</option>
                </select>
              </label>
              <div style={{ display: 'flex', gap: '0.6rem', flexWrap: 'wrap' }}>
                <button type="submit" style={{ ...listNavBtnStyle, backgroundColor: theme.primary, color: '#fff', borderColor: theme.primary, flex: 1 }}>
                  Найти
                </button>
                {(searchFilled(searchDraft) || filtering) && (
                  <button type="button" onClick={resetSearch} style={{ ...backBtnStyle, flex: 1 }}>
                    Сбросить
                  </button>
                )}
              </div>
            </div>
          </form>

          {listError && (
            <div style={{ ...innerCardStyle, marginBottom: '1.5rem', color: theme.error.text, backgroundColor: theme.error.bg, borderColor: theme.error.border }}>
              {listError}
            </div>
          )}

          {taskList.length === 0 ? (
            <div style={{ ...innerCardStyle, textAlign: 'center', padding: '5rem', color: theme.textMuted }}>{filtering ? 'Ничего не найдено' : 'Список пуст'}</div>
          ) : (
            <>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                {taskList.map((task, index) => {
                  const globalIndex = totalTasks - ((currentPage - 1) * itemsPerPage + index);
                  const result = applicabilityView(task.applicability);
                  let iconColors = theme.pending;
                  let iconMark = '•';
                  if (task.status === 'COMPLETED') {
                    iconColors = result?.colors || theme.success;
                    iconMark = result?.mark || '✓';
                  } else if (task.status === 'FAILED') {
                    iconColors = theme.error;
                    iconMark = '✕';
                  } else if (task.status === 'RUNNING') {
                    iconColors = theme.running;
                  }

                  return (
                    <div key={task.id} style={{ ...innerCardStyle, display: 'flex', alignItems: 'center', gap: '1.5rem', padding: '1.5rem 2rem', cursor: 'pointer', transition: 'all 0.2s', flexWrap: 'wrap' }} onClick={() => window.location.href = `/analysis/${task.id}`} onMouseEnter={e => { e.currentTarget.style.borderColor = theme.primary; e.currentTarget.style.transform = 'translateX(4px)'; }} onMouseLeave={e => { e.currentTarget.style.borderColor = 'rgba(203, 213, 225, 0.6)'; e.currentTarget.style.transform = 'translateX(0)'; }}>
                      <div style={{ fontSize: '1.5rem', fontWeight: '800', color: theme.borderDark, width: '40px', textAlign: 'right', flexShrink: 0, opacity: 0.6 }}>{globalIndex}</div>

                      <div style={{ width: '48px', height: '48px', borderRadius: '50%', backgroundColor: iconColors.bg, display: 'flex', alignItems: 'center', justifyContent: 'center', color: iconColors.text, fontSize: '1.25rem', fontWeight: 'bold', flexShrink: 0, border: `1px solid ${iconColors.border}` }}>
                        {task.status === 'RUNNING' ? (
                          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ animation: 'spin 2s linear infinite' }}>
                            <circle cx="12" cy="12" r="10"></circle>
                            <polyline points="12 6 12 12 16 14"></polyline>
                          </svg>
                        ) : iconMark}
                      </div>

                      <div style={{ flex: 1, minWidth: '240px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.4rem', flexWrap: 'wrap' }}>
                          <span style={{ fontWeight: '800', fontSize: '1.2rem', color: theme.textMain }}>{task.cve_id}</span>
                          {renderStatusBadge(task.status)}
                          {renderApplicabilityBadge(task.applicability)}
                          {task.rating ? <StarRow value={task.rating} size={18} /> : null}
                          <span style={{ fontSize: '0.9rem', color: theme.textMuted }}>{formatDateTime(task.created_at)}</span>
                        </div>
                        <div style={{ fontSize: '0.95rem', color: theme.textMuted, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {task.component_url} • {task.branch} • {task.package_name}
                        </div>
                      </div>

                      {showDuration(task.status, task.duration_ms) && (
                        <div style={{ flexShrink: 0, textAlign: 'right', minWidth: '88px' }}>
                          <div style={{ fontSize: '0.75rem', fontWeight: '700', letterSpacing: '0.04em', textTransform: 'uppercase', color: theme.textMuted, marginBottom: '0.25rem' }}>Время</div>
                          <div style={{ fontSize: '1.05rem', fontWeight: '800', color: theme.textMain }}>{formatDuration(task.duration_ms)}</div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>

              {totalPages > 1 && (
                <div style={{ display: 'flex', justifyContent: 'center', gap: '0.5rem', marginTop: '2.5rem' }}>
                  <button
                    disabled={currentPage === 1}
                    onClick={() => setCurrentPage(p => p - 1)}
                    style={{
                      width: '44px', height: '44px', borderRadius: '0.75rem', border: 'none',
                      backgroundColor: 'rgba(255,255,255,0.6)', color: theme.textMuted,
                      fontSize: '1rem', fontWeight: '700', cursor: currentPage === 1 ? 'default' : 'pointer',
                      opacity: currentPage === 1 ? 0.5 : 1
                    }}
                  >
                    ←
                  </button>
                  <span style={{ display: 'flex', alignItems: 'center', color: theme.textMuted, fontWeight: '600' }}>
                    Страница {currentPage} из {totalPages}
                  </span>
                  <button
                    disabled={currentPage === totalPages}
                    onClick={() => setCurrentPage(p => p + 1)}
                    style={{
                      width: '44px', height: '44px', borderRadius: '0.75rem', border: 'none',
                      backgroundColor: 'rgba(255,255,255,0.6)', color: theme.textMuted,
                      fontSize: '1rem', fontWeight: '700', cursor: currentPage === totalPages ? 'default' : 'pointer',
                      opacity: currentPage === totalPages ? 0.5 : 1
                    }}
                  >
                    →
                  </button>
                </div>
              )}
            </>
          )}
        </div>

        <style>{`
          @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
          }
        `}</style>
      </div>
    );
  }

  return (
    <div style={fullPageStyle}>
      <div style={boardContainerStyle}>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.6rem', marginBottom: '0.85rem' }}>
          <a
            href="/analysis/reviews"
            style={quietLinkStyle}
            onMouseEnter={e => paintQuietLink(e.currentTarget, true)}
            onMouseLeave={e => paintQuietLink(e.currentTarget, false)}
          >
            Отзывы
          </a>
          <SwaggerButton />
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '3.5rem', flexWrap: 'wrap', gap: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
            <div style={{ width: '64px', height: '64px', borderRadius: '50%', backgroundColor: theme.primary, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff', boxShadow: '0 8px 16px -4px rgba(37, 99, 235, 0.25)' }}>
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
            </div>
            <div>
              <h1 style={{ margin: 0, fontSize: '2.25rem', fontWeight: '800', color: theme.textMain }}>CVE Verdict</h1>
              <p style={{ margin: '0.5rem 0 0', color: theme.textMuted, fontSize: '1.1rem' }}>Запусти анализ применимости уязвимости к конкретному проекту</p>
            </div>
          </div>
          <div style={navBtnGroupStyle}>
            <button onClick={() => window.location.href = '/analysis/list'} style={listNavBtnStyle} onMouseEnter={e => { e.currentTarget.style.backgroundColor = theme.primary; e.currentTarget.style.color = '#fff'; }} onMouseLeave={e => { e.currentTarget.style.backgroundColor = '#fff'; e.currentTarget.style.color = theme.primary; }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="8" y1="6" x2="21" y2="6" /><line x1="8" y1="12" x2="21" y2="12" /><line x1="8" y1="18" x2="21" y2="18" /><line x1="3" y1="6" x2="3.01" y2="6" /><line x1="3" y1="12" x2="3.01" y2="12" /><line x1="3" y1="18" x2="3.01" y2="18" /></svg>
              Список анализов
            </button>
            <button onClick={() => window.location.href = '/'} style={backBtnStyle} onMouseEnter={e => { e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.5)'; e.currentTarget.style.borderColor = theme.primary; e.currentTarget.style.color = theme.primary; }} onMouseLeave={e => { e.currentTarget.style.backgroundColor = 'transparent'; e.currentTarget.style.borderColor = theme.borderDark; e.currentTarget.style.color = theme.textMuted; }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" /><polyline points="9 22 9 12 15 12 15 22" /></svg>
              Вернуться в CVE Patch Analyzer
            </button>
          </div>
        </div>

        <div style={{ maxWidth: '850px', margin: '0 auto' }}>
          <div style={{ ...innerCardStyle, padding: '3rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem', marginBottom: '2rem' }}>
              <h2 style={{ fontSize: '1.35rem', fontWeight: '800', color: theme.textMain, margin: 0 }}>Введите 4 параметра</h2>

              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '0.65rem' }}>
                <ModelPicker value={selectedModel} onChange={setSelectedModel} />
                {(formData.url || formData.branch || formData.cveId || formData.packageName) && (
                  <button
                    onClick={handleClearForm}
                    style={{
                      display: 'inline-flex', alignItems: 'center', gap: '0.5rem',
                      padding: '0.6rem 1.25rem', borderRadius: '0.75rem',
                      border: `1px solid ${theme.border}`, background: '#ffffff',
                      color: theme.textMuted, fontSize: '0.9rem', fontWeight: '600',
                      cursor: 'pointer', transition: 'all 0.2s',
                      boxShadow: '0 2px 4px rgba(0,0,0,0.05)'
                    }}
                    onMouseEnter={e => { e.currentTarget.style.backgroundColor = '#FEF2F2'; e.currentTarget.style.borderColor = '#FCA5A5'; e.currentTarget.style.color = '#991B1B'; }}
                    onMouseLeave={e => { e.currentTarget.style.backgroundColor = '#ffffff'; e.currentTarget.style.borderColor = theme.border; e.currentTarget.style.color = theme.textMuted; }}
                  >
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" /></svg>
                    Очистить
                  </button>
                )}
              </div>
            </div>

            {createError && (
              <div style={{
                marginBottom: '2rem',
                padding: '1.25rem',
                borderRadius: '0.75rem',
                backgroundColor: theme.error.bg,
                border: `1px solid ${theme.error.border}`,
                color: theme.error.text,
                display: 'flex',
                alignItems: 'center',
                gap: '0.75rem'
              }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
                </svg>
                <span style={{ fontWeight: '600', fontSize: '1rem' }}>{createError}</span>
              </div>
            )}

            <SuggestField
              label="Ссылка на компонент"
              placeholder="https://git.slo/dapp/dapp-grafana.git"
              value={formData.url}
              onChange={(url) => setFormData((prev) => ({ ...prev, url }))}
              load={(q) => apiService.suggestProjects(q)}
              onPick={(item) => setFormData((prev) => ({
                ...prev,
                url: item.url,
                branch: prev.branch || item.default_branch || ''
              }))}
              itemKey={(item) => item.url}
              itemText={(item) => item.path}
              itemHint={(item) => item.default_branch ? `ветка ${item.default_branch}` : ''}
            />
            <SuggestField
              label="Имя ветки"
              placeholder="main / release-1.31"
              value={formData.branch}
              onChange={(branch) => setFormData((prev) => ({ ...prev, branch }))}
              reloadKey={formData.url}
              load={(q) => apiService.suggestBranches(formData.url, q)}
              onPick={(item) => setFormData((prev) => ({ ...prev, branch: item.name }))}
              itemKey={(item) => item.name}
              itemText={(item) => item.name}
              itemHint={(item) => item.default ? 'по умолчанию' : ''}
            />
            {['cveId', 'packageName'].map((name, i) => (
              <div key={name} style={{ marginBottom: '2rem' }}>
                <label style={{ display: 'block', fontSize: '1.05rem', fontWeight: '700', marginBottom: '0.85rem', color: theme.textMain }}>
                  {['CVE ID или алиас', 'Уязвимый пакет'][i]} <span style={{ color: '#DC2626' }}>*</span>
                </label>
                <input name={name} style={fieldInputStyle} placeholder={['CVE-2025-22869', 'golang.org/x/crypto/ssh'][i]} value={formData[name]} onChange={e => setFormData({ ...formData, [name]: e.target.value })} onFocus={e => { e.target.style.borderColor = theme.primary; e.target.style.boxShadow = `0 0 0 4px ${theme.primaryLight}`; }} onBlur={e => { e.target.style.borderColor = theme.border; e.target.style.boxShadow = 'none'; }} />
              </div>
            ))}
            {typeof currentGo === 'string' && (
              <p style={{ margin: '0 0 1.25rem', color: theme.textMuted, fontSize: '0.95rem', fontWeight: '600' }}>
                {currentGo
                  ? `Актуальный Go: ${currentGo}`
                  : 'Актуальный Go не задан. Линейка без патча возьмёт последнюю опубликованную версию.'}
              </p>
            )}
            <button onClick={handleStartAnalysis} disabled={!formData.url || !formData.branch || !formData.cveId || !formData.packageName} style={{ backgroundColor: theme.primary, color: 'white', border: 'none', borderRadius: '0.75rem', padding: '1.25rem', fontWeight: '800', cursor: 'pointer', width: '100%', fontSize: '1.2rem', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.75rem', transition: 'all 0.2s', boxShadow: '0 4px 12px rgba(37, 99, 235, 0.25)', ...((!formData.url || !formData.branch || !formData.cveId || !formData.packageName) ? { backgroundColor: theme.textMuted, cursor: 'not-allowed', opacity: 0.6 } : {}) }} onMouseEnter={e => { if (formData.url) { e.currentTarget.style.backgroundColor = theme.primaryHover; e.currentTarget.style.transform = 'translateY(-2px)'; } }} onMouseLeave={e => { e.currentTarget.style.transform = 'translateY(0)'; if (formData.url) e.currentTarget.style.backgroundColor = theme.primary; }}>
              ▶ Запустить анализ
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

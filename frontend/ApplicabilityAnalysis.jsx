import React, { useState, useEffect } from 'react';
import { useParams, useLocation } from 'react-router-dom';

// --- REAL API SERVICE ---
const API_BASE = 'http://localhost:8741/api/v1/analysis';

const apiService = {
  createTask: async (data) => {
    const res = await fetch(API_BASE, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        component_url: data.url,
        branch: data.branch,
        cve_id: data.cveId,
        package_name: data.packageName
      })
    });

    const json = await res.json();

    if (!res.ok) {
      throw new Error(json.error || `Ошибка сервера (${res.status})`);
    }

    return json;
  },

  getTasks: async (limit = 10, offset = 0) => {
    const res = await fetch(`${API_BASE}?limit=${limit}&offset=${offset}`);
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

  downloadReportUrl: (id) => `${API_BASE}/${id}/report`
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
  if (hours > 0) return minutes ? `${hours} ч ${minutes} мин` : `${hours} ч`;
  if (minutes > 0) return seconds ? `${minutes} мин ${seconds} с` : `${minutes} мин`;
  return `${seconds} с`;
};

const showDuration = (status, ms) => status && status !== 'PENDING' && formatDuration(ms) !== '';

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
  const [createError, setCreateError] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [taskList, setTaskList] = useState([]);
  const [totalTasks, setTotalTasks] = useState(0);
  const itemsPerPage = 10;

  const [selectedModuleIndex, setSelectedModuleIndex] = useState(0);

  const isDetailView = !!taskId;
  const isListView = location.pathname.includes('/list');

  useEffect(() => {
    if (isListView) {
      const loadList = async () => {
        try {
          const data = await apiService.getTasks(itemsPerPage, (currentPage - 1) * itemsPerPage);
          setTaskList(data.list || []);
          setTotalTasks(data.total || 0);
        } catch (err) {
          console.error('Error loading list:', err);
        }
      };
      loadList();
    }
  }, [isListView, currentPage]);

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

  const handleStartAnalysis = async () => {
    if (!formData.url || !formData.branch || !formData.cveId || !formData.packageName) return;

    setCreateError('');

    try {
      const result = await apiService.createTask(formData);
      window.location.href = `/analysis/${result.id}`;
    } catch (err) {
      setCreateError(err.message || 'Произошла неизвестная ошибка при создании задачи');
    }
  };

  const handleClearForm = () => {
    setFormData({ url: '', branch: '', cveId: '', packageName: '' });
    setCreateError('');
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

  const handleCopyVerdict = async () => {
    const activeModule = currentTask?.modules?.[selectedModuleIndex];
    if (!activeModule?.verdict) return;
    await navigator.clipboard.writeText(activeModule.verdict);
    setCopiedVerdict(true);
    setTimeout(() => setCopiedVerdict(false), 2000);
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
      <span title="С момента запроса до последнего изменения статуса" style={pillStyle({ bg: '#FFFFFF', text: theme.textMuted, border: theme.border })}>
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

  if (isDetailView) {
    if (!currentTask) return <div style={fullPageStyle}><div style={boardContainerStyle}><div style={{ textAlign: 'center', padding: '6rem' }}><h2>Загрузка...</h2></div></div></div>;

    const isError = currentTask.status === 'FAILED';
    const isDone = currentTask.status === 'COMPLETED';
    const isRunning = currentTask.status === 'RUNNING';
    const isPending = currentTask.status === 'PENDING';
    const taskResult = applicabilityView(currentTask.applicability);
    const moduleResult = applicabilityView(activeModule?.applicability, 'module');
    const durationText = formatDuration(currentTask.duration_ms);

    let statusTheme;
    if (isError) statusTheme = theme.error;
    else if (isDone) statusTheme = moduleResult?.colors || taskResult?.colors || theme.success;
    else if (isRunning || isPending) statusTheme = theme.running;
    else statusTheme = theme.pending;

    const resultHint = isError
      ? 'Задача завершилась с ошибкой, поэтому результат неопределенный'
      : taskResult?.hint;

    return (
      <div style={fullPageStyle}>
        <div style={boardContainerStyle}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '3rem', flexWrap: 'wrap', gap: '1.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
              <div style={{ width: '64px', height: '64px', borderRadius: '50%', backgroundColor: theme.primary, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff', boxShadow: '0 8px 16px -4px rgba(37, 99, 235, 0.25)' }}>
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
              </div>
              <div>
                <h1 style={{ margin: 0, fontSize: '2.25rem', fontWeight: '800', color: theme.textMain }}>Детали анализа</h1>
                <p style={{ margin: '0.5rem 0 0', color: theme.textMuted, fontSize: '1.1rem' }}>
                  ID: {currentTask.id.slice(0, 8)}... • {formatDateTime(currentTask.created_at)}
                  {showDuration(currentTask.status, currentTask.duration_ms) ? ` • ${durationText}` : ''}
                </p>
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

          <div style={{ ...innerCardStyle, marginBottom: '2.5rem' }}>
            <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '1.25rem' }}>
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
              </div>
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
            ) : isError ? (
              <div style={{ padding: '3rem', textAlign: 'center', color: theme.error.text, fontWeight: '700', fontSize: '1.2rem', border: `1px solid ${theme.error.border}`, borderRadius: '1rem', backgroundColor: theme.error.bg, borderLeft: `8px solid ${theme.error.accent}` }}>
                Анализ завершился с ошибкой<br />
                <span style={{ fontSize: '1rem', fontWeight: '500', marginTop: '0.5rem', display: 'block' }}>{currentTask.error_msg}</span>
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

          <div>
            <h2 style={{ fontSize: '1.35rem', fontWeight: '800', marginBottom: '1.5rem', color: theme.textMain }}>Полный отчет</h2>
            {(isRunning || isError || isPending) ? (
              <div style={{ padding: '3rem', textAlign: 'center', color: theme.textMuted, fontWeight: '500', border: `2px dashed ${theme.border}`, borderRadius: '1rem', backgroundColor: 'rgba(255,255,255,0.4)' }}>
                {isError ? `Ошибка: ${currentTask.error_msg}` : 'Отчет сформируется позже'}
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

    return (
      <div style={fullPageStyle}>
        <div style={boardContainerStyle}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '3rem', flexWrap: 'wrap', gap: '1.5rem' }}>
            <div>
              <h1 style={{ margin: 0, fontSize: '2.25rem', fontWeight: '800', color: theme.textMain }}>Список анализов</h1>
              <p style={{ margin: '0.5rem 0 0', color: theme.textMuted, fontSize: '1.1rem' }}>История проверок ({totalTasks} всего)</p>
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

          {taskList.length === 0 ? (
            <div style={{ ...innerCardStyle, textAlign: 'center', padding: '5rem', color: theme.textMuted }}>Список пуст</div>
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
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '3.5rem', flexWrap: 'wrap', gap: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
            <div style={{ width: '64px', height: '64px', borderRadius: '50%', backgroundColor: theme.primary, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff', boxShadow: '0 8px 16px -4px rgba(37, 99, 235, 0.25)' }}>
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
            </div>
            <div>
              <h1 style={{ margin: 0, fontSize: '2.25rem', fontWeight: '800', color: theme.textMain }}>Анализ применимости уязвимости</h1>
              <p style={{ margin: '0.5rem 0 0', color: theme.textMuted, fontSize: '1.1rem' }}>Быстрая проверка репозитория на наличие CVE.</p>
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
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
              <h2 style={{ fontSize: '1.35rem', fontWeight: '800', color: theme.textMain, margin: 0 }}>Введите 4 параметра</h2>

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

            {['url', 'branch', 'cveId', 'packageName'].map((name, i) => (
              <div key={name} style={{ marginBottom: '2rem' }}>
                <label style={{ display: 'block', fontSize: '1.05rem', fontWeight: '700', marginBottom: '0.85rem', color: theme.textMain }}>
                  {['Ссылка на компонент', 'Имя ветки', 'CVE ID или алиас', 'Уязвимый пакет'][i]} <span style={{ color: '#DC2626' }}>*</span>
                </label>
                <input name={name} style={{ border: `1px solid ${theme.border}`, borderRadius: '0.75rem', padding: '1.1rem 1.35rem', fontSize: '1.1rem', width: '100%', boxSizing: 'border-box', outline: 'none', backgroundColor: 'rgba(255,255,255,0.8)', transition: 'all 0.2s', color: theme.textMain }} placeholder={['https://gitlab.com/org/project.git', 'main / release-1.31', 'CVE-2025-22869', 'golang.org/x/crypto/ssh'][i]} value={formData[name]} onChange={e => setFormData({ ...formData, [name]: e.target.value })} onFocus={e => { e.target.style.borderColor = theme.primary; e.target.style.boxShadow = `0 0 0 4px ${theme.primaryLight}`; }} onBlur={e => { e.target.style.borderColor = theme.border; e.target.style.boxShadow = 'none'; }} />
              </div>
            ))}
            <button onClick={handleStartAnalysis} disabled={!formData.url || !formData.branch || !formData.cveId || !formData.packageName} style={{ backgroundColor: theme.primary, color: 'white', border: 'none', borderRadius: '0.75rem', padding: '1.25rem', fontWeight: '800', cursor: 'pointer', width: '100%', fontSize: '1.2rem', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.75rem', transition: 'all 0.2s', boxShadow: '0 4px 12px rgba(37, 99, 235, 0.25)', ...((!formData.url || !formData.branch || !formData.cveId || !formData.packageName) ? { backgroundColor: theme.textMuted, cursor: 'not-allowed', opacity: 0.6 } : {}) }} onMouseEnter={e => { if (formData.url) { e.currentTarget.style.backgroundColor = theme.primaryHover; e.currentTarget.style.transform = 'translateY(-2px)'; } }} onMouseLeave={e => { e.currentTarget.style.transform = 'translateY(0)'; if (formData.url) e.currentTarget.style.backgroundColor = theme.primary; }}>
              ▶ Запустить анализ
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

import { type CSSProperties, type ReactNode, createContext, useContext, useEffect, useMemo, useState } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useAnalyzeMessage, useAnalyzeUrl, useHealthCheck } from '@workspace/api-client-react';
import type { ThreatAssessment } from '@workspace/api-client-react';
import type { User } from 'firebase/auth';
import { ErrorBoundary } from '@/components/error-boundary';
import { Toaster } from '@/components/ui/toaster';
import { TooltipProvider } from '@/components/ui/tooltip';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { firebaseConfigured } from '@/lib/firebase';
import { useFirebaseAuth } from '@/lib/firebase-auth';
import { clearCloudHistory, deleteCloudHistoryItem, getCloudHistory, getCloudLanguage, getCloudLearningProgress, saveCloudHistory, saveCloudLanguage, saveCloudLearningProgress } from '@/lib/firebase-history';
import { Route, Switch, Link, useLocation, Router as WouterRouter } from 'wouter';
import {
  Activity, ArrowDownLeft, ArrowLeft, ArrowRight, BookOpen, Check, ChevronRight, CircleHelp,
  ClipboardCheck, Clock3, Eye, Globe2, House, Info, Languages, LockKeyhole,
  Gamepad2, Lightbulb, LogIn, Menu, MessageSquareText, Network, RotateCcw, Search, Shield, ShieldAlert, ShieldCheck, Sparkles,
  Trash2, TriangleAlert, X,
} from 'lucide-react';
import NotFound from '@/pages/not-found';

const queryClient = new QueryClient();
type Language = 'en' | 'hi' | 'te';
type HistoryRecord = {
  id: string; kind: 'url' | 'message'; hostname?: string; riskLevel: string; riskScore: number;
  indicators: ThreatAssessment['indicators']; recommendations: string[]; evaluatedAt: string;
};
const HISTORY_KEY = 'cybershield-local-history-v1';
const LEARNING_KEY = 'cybershield-learning-progress-v1';
const translations: Record<Language, Record<string, string>> = {
  en: { home: 'Overview', url: 'Check a link', message: 'Check a message', history: 'Scan history', learn: 'Learn', practice: 'Practice', settings: 'Settings', welcome: 'A steadier way to stay safe online.', intro: 'Check a link or message for common warning signs. No jargon, no panic.', scanUrl: 'Check a link', scanMsg: 'Check a message', recent: 'Recent checks', allHistory: 'See scan history', total: 'Checks completed', high: 'Needs a closer look', low: 'Low concern', safeTitle: 'Take a moment before you tap.', safety: 'This tool explains common signals. It does not visit links or check a live threat database.' },
  hi: { home: 'मुख्य पृष्ठ', url: 'लिंक जाँचें', message: 'संदेश जाँचें', history: 'स्कैन इतिहास', learn: 'सीखें', practice: 'अभ्यास', settings: 'सेटिंग्स', welcome: 'ऑनलाइन सुरक्षित रहने का सरल तरीका।', intro: 'लिंक या संदेश के सामान्य चेतावनी संकेत समझें। बिना घबराहट, सरल भाषा में।', scanUrl: 'लिंक जाँचें', scanMsg: 'संदेश जाँचें', recent: 'हाल की जाँच', allHistory: 'स्कैन इतिहास देखें', total: 'पूरी हुई जाँच', high: 'ध्यान से देखें', low: 'कम चिंता', safeTitle: 'टैप करने से पहले एक पल रुकें।', safety: 'यह टूल सामान्य संकेत समझाता है। यह लिंक नहीं खोलता और लाइव खतरा डेटाबेस नहीं जाँचता।' },
  te: { home: 'ముఖ్య పేజీ', url: 'లింక్ తనిఖీ', message: 'సందేశం తనిఖీ', history: 'స్కాన్ చరిత్ర', learn: 'నేర్చుకోండి', practice: 'సాధన', settings: 'సెట్టింగ్‌లు', welcome: 'ఆన్‌లైన్‌లో సురక్షితంగా ఉండటానికి సులభమైన మార్గం.', intro: 'లింక్ లేదా సందేశంలోని సాధారణ హెచ్చరిక సంకేతాలను తెలుసుకోండి. భయం లేకుండా.', scanUrl: 'లింక్ తనిఖీ', scanMsg: 'సందేశం తనిఖీ', recent: 'ఇటీవలి తనిఖీలు', allHistory: 'స్కాన్ చరిత్ర చూడండి', total: 'పూర్తయిన తనిఖీలు', high: 'మరింత పరిశీలించండి', low: 'తక్కువ ఆందోళన', safeTitle: 'తాకే ముందు కాసేపు ఆగండి.', safety: 'ఈ సాధనం సాధారణ సంకేతాలను వివరిస్తుంది. ఇది లింక్‌లను తెరవదు లేదా ప్రత్యక్ష ముప్పు డేటాబేస్‌ను తనిఖీ చేయదు.' },
};
type AppContextValue = {
  language: Language; setLanguage: (language: Language) => void;
  history: HistoryRecord[]; addAssessment: (assessment: ThreatAssessment, hostname?: string) => void;
  removeHistory: (id: string) => void; clearHistory: () => void;
  result: ThreatAssessment | null; setResult: (result: ThreatAssessment) => void;
  user: User | null; authReady: boolean; authConfigured: boolean; authError: string;
  signIn: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string) => Promise<void>;
  logOut: () => Promise<void>; clearAuthError: () => void;
  historySource: 'local' | 'cloud'; historyError: string;
  completedLessons: string[]; markLessonCompleted: (id: string) => void;
};
const AppContext = createContext<AppContextValue | null>(null);
function useApp() { const value = useContext(AppContext); if (!value) throw new Error('App context unavailable'); return value; }
function copy(language: Language) { return translations[language]; }
function readHistory(): HistoryRecord[] {
  try { const parsed = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]'); return Array.isArray(parsed) ? parsed : []; } catch { return []; }
}
function readLearningProgress(): string[] {
  try { const parsed = JSON.parse(localStorage.getItem(LEARNING_KEY) || '[]'); return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === 'string') : []; } catch { return []; }
}
function AppProvider({ children }: { children: ReactNode }) {
  const auth = useFirebaseAuth();
  const [language, setLanguageState] = useState<Language>(() => (localStorage.getItem('cybershield-language') as Language) || 'en');
  const [history, setHistory] = useState<HistoryRecord[]>(readHistory);
  const [result, setResult] = useState<ThreatAssessment | null>(null);
  const [historySource, setHistorySource] = useState<'local' | 'cloud'>('local');
  const [historyError, setHistoryError] = useState('');
  const [completedLessons, setCompletedLessons] = useState<string[]>(readLearningProgress);
  const persist = (items: HistoryRecord[]) => { setHistory(items); localStorage.setItem(HISTORY_KEY, JSON.stringify(items)); };
  useEffect(() => {
    if (!auth.ready) return;
    if (!auth.user) {
      setHistory(readHistory());
      setHistorySource('local');
      setHistoryError('');
      setCompletedLessons(readLearningProgress());
      return;
    }
    let active = true;
    setHistory([]);
    setHistorySource('cloud');
    setHistoryError('');
    Promise.all([
      getCloudHistory(auth.user.uid),
      getCloudLanguage(auth.user.uid),
      getCloudLearningProgress(auth.user.uid),
    ]).then(([records, savedLanguage, progress]) => {
      if (!active) return;
      setHistory(records);
      setCompletedLessons(progress);
      if (savedLanguage) {
        setLanguageState(savedLanguage);
        localStorage.setItem('cybershield-language', savedLanguage);
      }
    }).catch(() => {
      if (!active) return;
      setHistory([]);
      setHistoryError('Cloud data could not be loaded. Check Firestore rules and network access.');
    });
    return () => { active = false; };
  }, [auth.ready, auth.user?.uid]);
  const setLanguage = (next: Language) => {
    setLanguageState(next);
    localStorage.setItem('cybershield-language', next);
    if (auth.user) void saveCloudLanguage(auth.user.uid, next).catch(() => setHistoryError('Your language preference could not be saved to Firebase.'));
  };
  const addAssessment = (a: ThreatAssessment, hostname?: string) => {
    const next: HistoryRecord = { id: a.id, kind: a.kind, ...(hostname ? { hostname } : {}), riskLevel: a.riskLevel, riskScore: a.riskScore, indicators: a.indicators, recommendations: a.recommendations, evaluatedAt: a.evaluatedAt };
    if (auth.user) {
      void saveCloudHistory(auth.user.uid, next).then(() => setHistory(current => [next, ...current.filter(x => x.id !== next.id)].slice(0, 100))).catch(() => setHistoryError('This result could not be saved to cloud history. Its details remain in this session only.'));
      return;
    }
    persist([next, ...readHistory().filter(x => x.id !== a.id)].slice(0, 100));
  };
  const removeHistory = (id: string) => {
    if (auth.user) {
      void deleteCloudHistoryItem(auth.user.uid, id).then(() => setHistory(current => current.filter(item => item.id !== id))).catch(() => setHistoryError('This history item could not be deleted from Firebase.'));
      return;
    }
    persist(readHistory().filter(item => item.id !== id));
  };
  const clearHistory = () => {
    if (auth.user) {
      void clearCloudHistory(auth.user.uid).then(() => setHistory([])).catch(() => setHistoryError('Cloud history could not be cleared. Check Firestore rules and try again.'));
      return;
    }
    persist([]);
  };
  const markLessonCompleted = (id: string) => {
    setCompletedLessons(current => {
      const next = current.includes(id) ? current : [...current, id];
      if (auth.user) void saveCloudLearningProgress(auth.user.uid, id, true).catch(() => setHistoryError('Lesson progress could not be saved to Firebase.'));
      else localStorage.setItem(LEARNING_KEY, JSON.stringify(next));
      return next;
    });
  };
  return <AppContext.Provider value={{
    language, setLanguage, history, addAssessment, removeHistory, clearHistory, result, setResult,
    user: auth.user, authReady: auth.ready, authConfigured: firebaseConfigured, authError: auth.error,
    signIn: auth.signIn, register: auth.register, logOut: auth.logOut, clearAuthError: () => auth.setError(''),
    historySource, historyError, completedLessons, markLessonCompleted,
  }}>{children}</AppContext.Provider>;
}
function App() {
  return <QueryClientProvider client={queryClient}><TooltipProvider><WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, '')}><AppProvider><Router /></AppProvider></WouterRouter><Toaster /></TooltipProvider></QueryClientProvider>;
}
function Router() {
  const [location] = useLocation();
  return <RoutedErrorBoundary resetKey={location}><AppShell><Switch>
    <Route path="/" component={Dashboard} />
    <Route path="/scan/url" component={UrlScanner} />
    <Route path="/scan/message" component={MessageScanner} />
    <Route path="/results/:scanId" component={ResultPage} />
    <Route path="/history" component={HistoryPage} />
    <Route path="/learn" component={LearnPage} />
    <Route path="/practice" component={PracticePage} />
    <Route path="/login" component={LoginPage} />
    <Route path="/settings" component={SettingsPage} />
    <Route component={NotFound} />
  </Switch></AppShell></RoutedErrorBoundary>;
}
function RoutedErrorBoundary({ children, resetKey }: { children: ReactNode; resetKey: string }) { return <ErrorBoundary resetKey={resetKey}>{children}</ErrorBoundary>; }

const navItems = [
  { href: '/', key: 'home', icon: House },
  { href: '/scan/url', key: 'url', icon: Globe2 },
  { href: '/scan/message', key: 'message', icon: MessageSquareText },
  { href: '/history', key: 'history', icon: Clock3 },
  { href: '/learn', key: 'learn', icon: BookOpen },
  { href: '/practice', key: 'practice', icon: Gamepad2 },
];
function AppShell({ children }: { children: ReactNode }) {
  const [location] = useLocation(); const { language, setLanguage, user, historySource } = useApp(); const t = copy(language);
  const [menuOpen, setMenuOpen] = useState(false);
  return <div className="app-frame">
    <aside className="sidebar">
      <Link href="/" className="brand" data-testid="link-brand"><span className="brand-mark"><Shield size={21} /></span><span>cyber<span>shield</span><small>AI safety companion</small></span></Link>
      <div className="side-label">YOUR SPACE</div>
      <nav className="side-nav">{navItems.map(item => { const Icon = item.icon; const active = item.href === '/' ? location === '/' : location.startsWith(item.href); return <Link key={item.href} href={item.href} className={`nav-link ${active ? 'active' : ''}`} data-testid={`link-nav-${item.key}`}><Icon size={18} strokeWidth={1.8}/><span>{t[item.key]}</span>{active && <span className="nav-dot"/>}</Link>; })}</nav>
       <div className="side-bottom">
         <div className="sidebar-tip"><div className="tip-icon"><LockKeyhole size={16}/></div><strong>Your privacy matters</strong><p>{historySource === 'cloud' ? 'Metadata-only history is in your Firebase account.' : 'Scan history stays in this browser, on this device.'}</p><Link href="/settings" data-testid="link-privacy-settings">Privacy settings <ArrowRight size={13}/></Link></div>
        <Link href="/settings" className={`nav-link ${location === '/settings' ? 'active' : ''}`} data-testid="link-nav-settings"><Activity size={18}/><span>{t.settings}</span></Link>
        <Link href="/login" className={`nav-link ${location === '/login' ? 'active' : ''}`} data-testid="link-nav-login"><LogIn size={18}/><span>Account</span></Link>
      </div>
      <div className="sidebar-foot"><span className="status-led"/><span>Rule-based checks</span><span className="version">v1.0</span></div>
    </aside>
    <div className="main-column">
      <header className="topbar">
        <button className="mobile-menu" aria-label="Open navigation" onClick={() => setMenuOpen(!menuOpen)} data-testid="button-mobile-menu">{menuOpen ? <X size={20}/> : <Menu size={20}/>}</button>
        <div className="crumb"><span>CyberShield</span><ChevronRight size={14}/><strong>{navItems.find(n => n.href === location)?.key ? t[navItems.find(n => n.href === location)!.key] : location.startsWith('/results') ? 'Assessment' : location.split('/').filter(Boolean).pop()?.replace(/^\w/, c => c.toUpperCase())}</strong></div>
         <div className="top-actions"><div className="language-chip"><Languages size={15}/><select aria-label="Choose language" value={language} onChange={e => setLanguage(e.target.value as Language)} data-testid="select-language"><option value="en">EN</option><option value="hi">हि</option><option value="te">తె</option></select></div><Link href="/login" className="profile-button" data-testid="link-account"><span className="profile-dot">{user?.email?.[0]?.toUpperCase() || 'G'}</span><span>{user?.email?.split('@')[0] || 'Guest'}</span></Link></div>
      </header>
      {menuOpen && <div className="mobile-nav">{navItems.map(n => <Link key={n.href} href={n.href} onClick={() => setMenuOpen(false)} data-testid={`mobile-link-${n.key}`}>{copy(language)[n.key]}</Link>)}<Link href="/settings" onClick={() => setMenuOpen(false)}>Settings</Link></div>}
      <main className="content">{children}</main>
      <footer className="page-footer"><span>Made for everyday confidence online.</span><span><ShieldCheck size={14}/> No links are opened during checks.</span></footer>
    </div>
  </div>;
}
function PageHeading({ eyebrow, title, description, children }: { eyebrow?: string; title: string; description?: string; children?: ReactNode }) {
  return <div className="page-heading"><div><div className="eyebrow">{eyebrow || 'CYBERSHIELD AI'}</div><h1>{title}</h1>{description && <p>{description}</p>}</div>{children}</div>;
}
function Card({ children, className = '' }: { children: ReactNode; className?: string }) { return <section className={`panel ${className}`}>{children}</section>; }
function RiskTag({ risk }: { risk: string }) { return <span className={`risk-tag risk-${risk.toLowerCase()}`}><span/>{risk === 'low' ? 'Low concern' : risk === 'medium' ? 'Review carefully' : 'Higher concern'}</span>; }
function formatTime(value: string) { const d = new Date(value); return Number.isNaN(d.getTime()) ? 'Time unavailable' : new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }).format(d); }

function Dashboard() {
  const { history, language, historySource } = useApp(); const t = copy(language); const high = history.filter(x => x.riskLevel === 'high').length; const medium = history.filter(x => x.riskLevel === 'medium').length; const low = history.filter(x => x.riskLevel === 'low').length; const suspiciousUrls = history.filter(x => x.kind === 'url' && x.riskLevel !== 'low').length; const suspiciousMessages = history.filter(x => x.kind === 'message' && x.riskLevel !== 'low').length; const health = useHealthCheck();
  return <div className="page-wrap">
    <div className="welcome-hero">
      <div className="hero-copy"><div className="eyebrow pale">A LITTLE MORE CLARITY</div><h1>{t.welcome}</h1><p>{t.intro}</p><div className="hero-actions"><Link href="/scan/url" className="button-primary" data-testid="link-hero-url"><Globe2 size={17}/>{t.scanUrl}<ArrowRight size={16}/></Link><Link href="/scan/message" className="button-quiet" data-testid="link-hero-message"><MessageSquareText size={17}/>{t.scanMsg}</Link></div></div>
      <div className="hero-art" aria-hidden="true"><div className="orbit orbit-one"/><div className="orbit orbit-two"/><div className="hero-shield"><ShieldCheck size={68} strokeWidth={1.3}/><span className="shield-spark"><Sparkles size={17}/></span></div><div className="orbit-node node-a"/><div className="orbit-node node-b"/><div className="orbit-node node-c"/><div className="art-caption"><span className="status-led"/>A calm second opinion</div></div>
      <div className="hero-footnote"><Info size={14}/>{t.safety}</div>
    </div>
    <div className="stats-grid">
      <StatCard label={t.total} value={history.length} sub={historySource === 'cloud' ? 'Saved to your account' : 'Saved on this device'} icon={<ClipboardCheck size={18}/>} tone="blue"/>
      <StatCard label="Suspicious links" value={suspiciousUrls} sub="Medium or high signal score" icon={<Globe2 size={18}/>} tone="gold"/>
      <StatCard label="Potentially fraudulent messages" value={suspiciousMessages} sub="Medium or high signal score" icon={<MessageSquareText size={18}/>} tone="mint"/>
      <StatCard label="High concern" value={high} sub="Pause and verify another way" icon={<TriangleAlert size={18}/>} tone="soft"/>
    </div>
    <div className="risk-summary" data-testid="summary-threat-levels"><div className="risk-summary-head"><strong>Threat level overview</strong><span>{history.length} {history.length === 1 ? 'check' : 'checks'}</span></div><div className="risk-track" role="img" aria-label={`Risk level distribution: ${low} low, ${medium} medium, ${high} high`}><span className="risk-segment low" style={{ width: `${history.length ? low / history.length * 100 : 0}%` }}/><span className="risk-segment medium" style={{ width: `${history.length ? medium / history.length * 100 : 0}%` }}/><span className="risk-segment high" style={{ width: `${history.length ? high / history.length * 100 : 0}%` }}/></div><div className="risk-legend"><span><i className="low"/>Low <strong>{low}</strong></span><span><i className="medium"/>Medium <strong>{medium}</strong></span><span><i className="high"/>High <strong>{high}</strong></span></div></div>
    <div className="dashboard-grid">
      <Card className="recent-panel"><div className="section-head"><div><div className="eyebrow">YOUR ACTIVITY</div><h2>{t.recent}</h2></div><Link href="/history" className="text-link" data-testid="link-all-history">{t.allHistory}<ArrowRight size={15}/></Link></div>
        {history.length ? <div className="activity-list">{history.slice(0, 5).map(item => <Link href={`/results/${item.id}`} className="activity-row" key={item.id} data-testid={`row-recent-${item.id}`}><span className={`activity-icon ${item.kind}`} >{item.kind === 'url' ? <Globe2 size={17}/> : <MessageSquareText size={17}/>}</span><span className="activity-info"><strong>{item.kind === 'url' ? item.hostname || 'Link check' : 'Message check'}</strong><small>{formatTime(item.evaluatedAt)} · {item.kind === 'url' ? 'Link' : 'Message'}</small></span><RiskTag risk={item.riskLevel}/><ChevronRight className="row-chevron" size={17}/></Link>)}</div> : <EmptyActivity/>}
      </Card>
      <Card className="quick-panel"><div className="eyebrow">QUICK CHECK</div><h2>What would you like to review?</h2><p>Choose what you received. We’ll explain the signals in plain language.</p><Link href="/scan/url" className="quick-action" data-testid="link-quick-url"><span className="quick-icon blue"><Globe2 size={19}/></span><span><strong>A web link</strong><small>Look at a URL without opening it</small></span><ArrowRight size={16}/></Link><Link href="/scan/message" className="quick-action" data-testid="link-quick-message"><span className="quick-icon teal"><MessageSquareText size={19}/></span><span><strong>A text or email</strong><small>Review wording for common signs</small></span><ArrowRight size={16}/></Link><div className="health-note"><span className={`status-led ${health.isError ? 'offline' : ''}`}/>{health.isError ? 'Analysis service is currently unavailable.' : `Analysis service: ${health.data?.status === 'ok' ? 'ready' : 'checking'}.`}</div></Card>
    </div>
    <div className="learning-banner"><div className="learn-symbol"><BookOpen size={21}/></div><div><strong>Build confidence, one small lesson at a time.</strong><p>Learn how to spot pressure tactics and protect your accounts.</p></div><Link href="/learn" className="text-link" data-testid="link-learning">Browse lessons <ArrowRight size={15}/></Link></div>
  </div>;
}
function StatCard({ label, value, sub, icon, tone }: { label: string; value: ReactNode; sub: string; icon: ReactNode; tone: string }) { return <div className="stat-card" data-testid={`stat-${tone}`}><div className={`stat-icon ${tone}`}>{icon}</div><div className="stat-label">{label}</div><div className="stat-value">{value}</div><div className="stat-sub">{sub}</div></div>; }
function EmptyActivity() { return <div className="empty-activity"><div className="empty-icon"><Search size={23}/></div><strong>No checks yet</strong><p>Your local scan history will show here after your first check.</p><Link href="/scan/url" className="text-link" data-testid="link-empty-scan">Start with a link <ArrowRight size={14}/></Link></div>; }

const urlSchema = z.object({ url: z.string().trim().min(1, 'Enter a link to check.').max(4096, 'This link is too long.') });
const messageSchema = z.object({ message: z.string().trim().min(1, 'Enter some message text to review.').max(10000, 'Please keep the message under 10,000 characters.') });
function ScanLayout({ type, children }: { type: 'url' | 'message'; children: ReactNode }) {
  return <div className="page-wrap"><PageHeading eyebrow={type === 'url' ? 'LINK CHECK' : 'MESSAGE CHECK'} title={type === 'url' ? 'Check a web link' : 'Check a message'} description={type === 'url' ? 'Review the shape of a link without visiting the website.' : 'Look for common wording patterns that deserve a second look.'}/><div className="scan-layout"><div>{children}</div><ScanSideInfo kind={type}/></div></div>;
}
function ScanSideInfo({ kind }: { kind: string }) { return <div className="scan-aside"><div className="aside-stamp"><ShieldCheck size={20}/><span>SAFE TO REVIEW</span></div><h3>Your information stays yours.</h3><p>{kind === 'url' ? 'We analyze the text of a link. We never open or visit the website.' : 'Message text is sent for analysis and is not saved in local scan history.'}</p><div className="aside-divider"/><div className="aside-point"><LockKeyhole size={16}/><span>History stores only scan metadata on this device.</span></div><div className="aside-point"><Eye size={16}/><span>Results come from transparent rules, not a trained model.</span></div><div className="aside-point"><Network size={16}/><span>No live threat database is checked.</span></div><div className="aside-caution"><CircleHelp size={16}/><span>A result is one perspective—not proof that something is safe or fraudulent.</span></div></div>; }
function UrlScanner() {
  const form = useForm<z.infer<typeof urlSchema>>({ resolver: zodResolver(urlSchema), defaultValues: { url: '' } });
  const scan = useAnalyzeUrl(); const { language, addAssessment, setResult } = useApp(); const [, setLocation] = useLocation(); const [error, setError] = useState('');
  const submit = form.handleSubmit(values => { setError(''); scan.mutate({ data: { url: values.url.trim(), language } }, { onSuccess: assessment => { let hostname = ''; try { hostname = new URL(values.url.trim().startsWith('http') ? values.url.trim() : `https://${values.url.trim()}`).hostname; } catch { hostname = values.url.trim().split('/')[0]; } addAssessment(assessment, hostname); setResult(assessment); setLocation(`/results/${assessment.id}`); }, onError: () => setError('We couldn’t complete this check right now. Please try again in a moment.') }); });
  const examples = ['https://accounts.example.com/verify', 'http://short-link.example/claim'];
  return <ScanLayout type="url"><Card className="scan-card"><div className="scan-card-head"><span className="form-icon url-icon"><Globe2 size={20}/></span><div><h2>Paste the link here</h2><p>It stays unopened while we review it.</p></div></div><Form {...form}><form onSubmit={submit} className="form-stack"><FormField control={form.control} name="url" render={({ field }) => <FormItem><FormLabel>Web address</FormLabel><FormControl><div className="input-with-icon"><Globe2 size={17}/><Input {...field} placeholder="https://example.com/page" autoComplete="url" data-testid="input-url"/></div></FormControl><FormMessage/></FormItem>}/><div className="privacy-inline"><LockKeyhole size={14}/> The URL is analyzed as text. The site is never opened.</div>{error && <div className="form-error" role="alert" data-testid="status-url-error"><TriangleAlert size={16}/>{error}<button type="button" onClick={() => setError('')} aria-label="Dismiss error"><X size={14}/></button></div>}<Button type="submit" className="submit-button" disabled={scan.isPending} data-testid="button-submit-url">{scan.isPending ? <><span className="button-pulse"/>Reviewing link…</> : <>Check this link <ArrowRight size={16}/></>}</Button></form></Form><DemoExamples values={examples} label="EXAMPLE LINKS — these will run through the real analyzer" onSelect={url => form.setValue('url', url, { shouldValidate: true })}/></Card></ScanLayout>;
}
function MessageScanner() {
  const form = useForm<z.infer<typeof messageSchema>>({ resolver: zodResolver(messageSchema), defaultValues: { message: '' } });
  const scan = useAnalyzeMessage(); const { language, addAssessment, setResult } = useApp(); const [, setLocation] = useLocation(); const [error, setError] = useState('');
  const submit = form.handleSubmit(values => { setError(''); scan.mutate({ data: { message: values.message.trim(), language } }, { onSuccess: assessment => { addAssessment(assessment); setResult(assessment); setLocation(`/results/${assessment.id}`); }, onError: () => setError('We couldn’t complete this check right now. Please try again in a moment.') }); });
  const examples = ['Your account will be closed today. Confirm your details at the link below to avoid losing access.', 'Hi, your delivery is waiting. Pay a small fee now to receive your parcel.'];
  return <ScanLayout type="message"><Card className="scan-card"><div className="scan-card-head"><span className="form-icon msg-icon"><MessageSquareText size={20}/></span><div><h2>Paste the message here</h2><p>We look for common patterns, not certainty.</p></div></div><Form {...form}><form onSubmit={submit} className="form-stack"><FormField control={form.control} name="message" render={({ field }) => <FormItem><FormLabel>Message text</FormLabel><FormControl><Textarea {...field} placeholder="Paste a message or email you’re unsure about…" className="message-input" data-testid="input-message"/></FormControl><div className="field-foot"><FormMessage/><span>{(form.watch('message') || '').length} / 10,000</span></div></FormItem>}/><div className="privacy-inline"><LockKeyhole size={14}/> Your pasted message is not saved in local history.</div>{error && <div className="form-error" role="alert" data-testid="status-message-error"><TriangleAlert size={16}/>{error}<button type="button" onClick={() => setError('')} aria-label="Dismiss error"><X size={14}/></button></div>}<Button type="submit" className="submit-button" disabled={scan.isPending} data-testid="button-submit-message">{scan.isPending ? <><span className="button-pulse"/>Reviewing message…</> : <>Review this message <ArrowRight size={16}/></>}</Button></form></Form><DemoExamples values={examples} label="EXAMPLE MESSAGES — these will run through the real analyzer" onSelect={message => form.setValue('message', message, { shouldValidate: true })}/></Card></ScanLayout>;
}
function DemoExamples({ values, label, onSelect }: { values: string[]; label: string; onSelect: (value: string) => void }) { return <div className="examples"><div className="example-heading"><Sparkles size={14}/>{label}</div><div className="example-list">{values.map((value, i) => <button key={value} type="button" className="example-button" onClick={() => onSelect(value)} data-testid={`button-example-${i}`}><span>Example {String(i + 1).padStart(2, '0')}</span><p>{value}</p><ArrowDownLeft size={15}/></button>)}</div></div>; }

function ResultPage() {
  const params = useLocation()[0].split('/'); const scanId = params[2]; const { result, history, language } = useApp();
  const assessment = result?.id === scanId ? result : null; const record = history.find(h => h.id === scanId);
  if (!assessment && !record) return <div className="page-wrap"><PageHeading title="Assessment unavailable" description="This result is no longer in this session or local history."/><Card className="unavailable-card"><div className="empty-icon"><Info size={22}/></div><p>For your privacy, detailed results are held only for the current session. Scan metadata may remain in local history.</p><Link href="/history" className="button-primary" data-testid="link-result-history">View local history <ArrowRight size={16}/></Link></Card></div>;
  const risk = assessment?.riskLevel || record!.riskLevel; const score = assessment?.riskScore ?? record!.riskScore; const indicators = assessment?.indicators || record!.indicators; const recommendations = assessment?.recommendations || record!.recommendations;
  const explanation = assessment?.explanation || 'The full explanation is available in the session where this assessment was made.'; const isHigh = risk === 'high';
  return <div className="page-wrap"><Link href="/history" className="back-link" data-testid="link-back-history"><ArrowLeft size={15}/>Back to history</Link><PageHeading eyebrow="ASSESSMENT DETAILS" title="Here’s what we noticed." description="A calm summary to help you choose your next step."/><div className={`result-overview ${risk}`}><div className="result-badge">{isHigh ? <ShieldAlert size={25}/> : <ShieldCheck size={25}/>}</div><div className="result-text"><RiskTag risk={risk}/><h2>{isHigh ? 'Pause before you respond.' : risk === 'medium' ? 'Worth a closer look.' : 'No common warning signs found.'}</h2><p>{explanation}</p></div><div className="score-box"><div className="score-ring" style={{ '--score': `${score}%` } as CSSProperties}><span>{score}</span></div><small>signal score</small></div></div>
    <div className="result-disclaimer"><Info size={17}/><span>This rule-based assessment is not a trained model or live threat database. One indicator alone does not prove fraud, and a low score cannot guarantee safety.</span></div>
    <div className="result-columns"><Card><div className="section-head"><div><div className="eyebrow">TRANSPARENT SIGNALS</div><h2>What we noticed</h2></div><span className="count-pill">{indicators.length}</span></div>{indicators.length ? <div className="indicator-list">{indicators.map((item, i) => <div className="indicator-item" key={`${item.code}-${i}`}><span className="indicator-mark"><Info size={16}/></span><div><strong>{item.title}</strong><p>{item.detail}</p></div></div>)}</div> : <div className="no-signals"><ShieldCheck size={18}/>No common indicators were found by these rules.</div>}</Card>
      <Card><div className="eyebrow">PRACTICAL NEXT STEPS</div><h2>What you can do</h2><div className="recommendations">{recommendations.map((rec, i) => <div className="recommendation" key={`${rec}-${i}`}><span>{String(i + 1).padStart(2, '0')}</span><p>{rec}</p></div>)}</div><div className="result-meta"><Clock3 size={14}/>{assessment?.engine || 'rule-based'} · {formatTime(assessment?.evaluatedAt || record!.evaluatedAt)} · {assessment?.language || language.toUpperCase()}</div></Card></div>
    <div className="result-actions"><Link href="/scan/url" className="button-primary" data-testid="link-new-url-scan">Check another link <ArrowRight size={15}/></Link><Link href="/scan/message" className="button-outline" data-testid="link-new-message-scan">Check a message</Link></div>
  </div>;
}

function HistoryPage() {
  const { history, removeHistory, clearHistory, historySource, historyError } = useApp(); const [confirmClear, setConfirmClear] = useState(false); const [filter, setFilter] = useState('all');
  const shown = useMemo(() => history.filter(x => filter === 'all' || x.kind === filter), [history, filter]);
  return <div className="page-wrap"><PageHeading eyebrow={historySource === 'cloud' ? 'FIREBASE ACCOUNT' : 'LOCAL ONLY'} title="Scan history" description="Only scan metadata is kept. Full links and message text are never stored.">{history.length > 0 && <Button variant="outline" className="clear-button" onClick={() => setConfirmClear(true)} data-testid="button-clear-history"><Trash2 size={15}/>Clear history</Button>}</PageHeading>
    <div className="history-privacy"><span className="privacy-lock"><LockKeyhole size={17}/></span><div><strong>{historySource === 'cloud' ? 'Synced to your Firebase account' : 'Stored on this device only'}</strong><p>History includes the link’s hostname (not its path), risk summary, and time. Message text is never kept.</p></div><span className="local-label">{historySource === 'cloud' ? 'CLOUD' : 'LOCAL'}</span></div>
    {historyError && <div className="form-error" role="alert" data-testid="status-history-error"><TriangleAlert size={16}/>{historyError}</div>}
    <Card className="history-card"><div className="history-toolbar"><div><h2>Your checks</h2><span>{history.length} {history.length === 1 ? 'record' : 'records'}</span></div><div className="filter-switch" role="group" aria-label="Filter history">{[['all','All'],['url','Links'],['message','Messages']].map(([key,label]) => <button key={key} className={filter === key ? 'selected' : ''} onClick={() => setFilter(key)} data-testid={`button-filter-${key}`}>{label}</button>)}</div></div>
      {shown.length ? <div className="history-list">{shown.map(item => <div className="history-row" key={item.id} data-testid={`row-history-${item.id}`}><Link className="history-row-link" href={`/results/${item.id}`} data-testid={`link-history-result-${item.id}`}><span className={`activity-icon ${item.kind}`}>{item.kind === 'url' ? <Globe2 size={17}/> : <MessageSquareText size={17}/>}</span><span className="activity-info"><strong>{item.kind === 'url' ? item.hostname || 'Link check' : 'Message check'}</strong><small>{formatTime(item.evaluatedAt)} · {item.indicators.length} {item.indicators.length === 1 ? 'signal' : 'signals'}</small></span><RiskTag risk={item.riskLevel}/><span className="history-score">{item.riskScore}<small>/100</small></span></Link><button className="icon-button" onClick={() => removeHistory(item.id)} aria-label={`Delete ${item.kind} check`} data-testid={`button-delete-${item.id}`}><Trash2 size={16}/></button></div>)}</div> : <div className="history-empty"><div className="empty-icon"><Clock3 size={23}/></div><strong>{history.length ? 'No checks in this filter' : 'Your history is clear'}</strong><p>{history.length ? 'Try another filter to see your saved checks.' : 'When you run a check, only its privacy-conscious summary appears here.'}</p>{!history.length && <Link href="/scan/url" className="button-primary" data-testid="link-history-empty-scan">Check a link <ArrowRight size={15}/></Link>}</div>}
    </Card>{confirmClear && <div className="confirm-scrim" role="presentation"><div className="confirm-dialog" role="alertdialog" aria-modal="true" aria-labelledby="clear-title"><span className="dialog-icon"><Trash2 size={20}/></span><h2 id="clear-title">Clear all local history?</h2><p>This removes {history.length} metadata record{history.length === 1 ? '' : 's'} from this browser. This cannot be undone.</p><div className="dialog-actions"><Button variant="outline" onClick={() => setConfirmClear(false)} data-testid="button-cancel-clear">Keep history</Button><Button variant="destructive" onClick={() => { clearHistory(); setConfirmClear(false); }} data-testid="button-confirm-clear">Clear history</Button></div></div></div>}
  </div>;
}

const lessons = [
  { id: 'pause', tag: '01 · THE PAUSE', title: 'Urgency is a signal, not an instruction.', time: '2 min', body: 'Scams often ask you to act now: a delivery fee, account closure, or prize that expires. Take a breath. Open the official app or type the known website address yourself rather than following a message link.', question: 'A text says your bank account closes in 10 minutes. What is the safest first move?', choices: ['Tap its link quickly', 'Contact your bank using its official app or number', 'Reply with your account details'], answer: 1, explain: 'Using a known official channel lets you check without trusting the message.' },
  { id: 'links', tag: '02 · LINKS', title: 'Read the address before you trust the page.', time: '3 min', body: 'A familiar logo can be copied. Look at the actual domain name: the part just before the final extension. Misspellings, extra words, and unexpected short links deserve care. If you are unsure, go to the service another way.', question: 'Which is the better way to reach a service you use?', choices: ['Use the link in an unexpected prize text', 'Type its known address or use its official app', 'Choose whichever link looks shorter'], answer: 1, explain: 'Known routes reduce the chance of landing on an imitation page.' },
  { id: 'codes', tag: '03 · YOUR ACCOUNTS', title: 'Keep one-time codes to yourself.', time: '2 min', body: 'Verification codes and password reset links are keys to your account. A real support agent should not ask you to read a one-time code aloud or send it in chat. If someone asks, end the conversation and contact the service independently.', question: 'Someone claiming to be support asks for a login code. What should you do?', choices: ['Share it to prove it is your account', 'Do not share it; contact support through an official channel', 'Post it in a group to ask what it is'], answer: 1, explain: 'A one-time code can let someone else enter your account.' },
  { id: 'payments', tag: '04 · PAYMENTS', title: 'Pause before unusual payment requests.', time: '3 min', body: 'Gift cards, cryptocurrency, or a transfer to a new account can be difficult to reverse. If a request is unexpected—even from someone you know—verify it with a separate phone call or in person before paying.', question: 'A familiar contact urgently asks for a gift card code. Best next step?', choices: ['Send the code and ask later', 'Verify with them through a separate trusted channel', 'Forward the request to more people'], answer: 1, explain: 'A separate channel can confirm whether the account was really theirs.' },
];
function LearnPage() {
  const [open, setOpen] = useState<string | null>(null); const [answers, setAnswers] = useState<Record<string, number>>({}); const [checked, setChecked] = useState<Record<string, boolean>>({}); const { completedLessons, markLessonCompleted } = useApp();
  const lesson = lessons.find(x => x.id === open);
  return <div className="page-wrap"><PageHeading eyebrow="LEARN AT YOUR PACE" title="Small habits. Stronger safety." description="Short, practical lessons for everyday moments online."/>{lesson ? <Card className="lesson-detail"><button className="back-link lesson-back" onClick={() => setOpen(null)} data-testid="button-back-lessons"><ArrowLeft size={15}/>All lessons</button><div className="eyebrow">{lesson.tag} · {lesson.time}</div><h2>{lesson.title}</h2><p className="lesson-body">{lesson.body}</p><div className="quiz-box"><div className="eyebrow">QUICK CHECK</div><h3>{lesson.question}</h3><div className="quiz-options">{lesson.choices.map((choice, i) => <button key={choice} className={`quiz-choice ${answers[lesson.id] === i ? 'chosen' : ''} ${checked[lesson.id] && i === lesson.answer ? 'correct' : ''}`} onClick={() => { setAnswers({ ...answers, [lesson.id]: i }); setChecked({ ...checked, [lesson.id]: false }); }} data-testid={`button-quiz-${lesson.id}-${i}`}><span className="choice-letter">{String.fromCharCode(65 + i)}</span>{choice}{checked[lesson.id] && i === lesson.answer && <Check size={17}/>}</button>)}</div>{checked[lesson.id] && <div className={`quiz-feedback ${answers[lesson.id] === lesson.answer ? 'right' : ''}`} data-testid={`status-quiz-${lesson.id}`}>{answers[lesson.id] === lesson.answer ? 'That’s right. ' : 'Not quite. '}{lesson.explain}</div>}<Button onClick={() => { const correct = answers[lesson.id] === lesson.answer; setChecked({ ...checked, [lesson.id]: true }); if (correct) markLessonCompleted(lesson.id); }} disabled={answers[lesson.id] === undefined} className="quiz-submit" data-testid={`button-check-quiz-${lesson.id}`}>{completedLessons.includes(lesson.id) ? 'Completed' : 'Check answer'} <ArrowRight size={15}/></Button></div></Card> : <div className="lesson-grid">{lessons.map((item, i) => <button className="lesson-card" key={item.id} onClick={() => setOpen(item.id)} data-testid={`button-lesson-${item.id}`}><span className="lesson-number">{String(i + 1).padStart(2, '0')}</span><span className="lesson-tag">{completedLessons.includes(item.id) ? 'COMPLETED' : item.tag}</span><h2>{item.title}</h2><p>{item.body.slice(0, 100)}…</p><span className="lesson-bottom"><span><Clock3 size={14}/>{item.time}</span><span>{completedLessons.includes(item.id) ? 'Review lesson' : 'Read lesson'} <ArrowRight size={15}/></span></span></button>)}</div>}
    <div className="learn-note"><Info size={15}/>Cyber safety is about reducing risk, not getting every decision perfect.</div><Link href="/practice" className="practice-promo" data-testid="link-practice-from-learn"><span className="practice-promo-icon"><Gamepad2 size={19}/></span><span><strong>Put your instincts into practice</strong><small>Try fictional simulations and learn from each choice.</small></span><ArrowRight size={17}/></Link>
  </div>;
}

type PracticeScenario = {
  id: string;
  sender: string;
  channel: string;
  message: string;
  clue: string;
  choices: { text: string; safe: boolean }[];
  explanation: string;
};

const practiceScenarios: PracticeScenario[] = [
  {
    id: 'bank-code',
    sender: 'Unverified sender',
    channel: 'SMS · FICTIONAL EXAMPLE',
    message: 'RiverBank alert: your account will be locked in 30 minutes. Reply with the verification code to keep access.',
    clue: 'It creates a deadline and asks you to share a one-time code.',
    choices: [
      { text: 'Reply with the code so the account stays open.', safe: false },
      { text: 'Open the bank app I already use or call the number on my card.', safe: true },
      { text: 'Forward the message to a friend and ask them to reply.', safe: false },
    ],
    explanation: 'A real bank should not ask you to share an OTP in a text. Open the app independently or use a phone number you already trust.',
  },
  {
    id: 'prize-fee',
    sender: 'Lucky Draw Desk',
    channel: 'CHAT MESSAGE · FICTIONAL EXAMPLE',
    message: 'Congratulations! You won a new phone. Pay a small release fee today to receive your prize.',
    clue: 'The prize is unexpected, and collecting it requires an upfront payment.',
    choices: [
      { text: 'Pay the fee quickly before the offer expires.', safe: false },
      { text: 'Verify the promotion through the company’s official website or app.', safe: true },
      { text: 'Send my bank details so they can transfer the prize.', safe: false },
    ],
    explanation: 'Unexpected prizes paired with fees or requests for financial details are a common warning pattern. Verify independently and do not pay to claim an unverified prize.',
  },
  {
    id: 'delivery-fee',
    sender: 'Parcel Updates',
    channel: 'SMS · FICTIONAL EXAMPLE',
    message: 'A parcel is waiting. Pay a small delivery fee using this message to arrange another delivery attempt.',
    clue: 'An unexpected payment request is tied to a delivery notice.',
    choices: [
      { text: 'Use the payment link in the unexpected text.', safe: false },
      { text: 'Check my order in the delivery company’s official app or site.', safe: true },
      { text: 'Send my card number by replying to the sender.', safe: false },
    ],
    explanation: 'Delivery-fee messages are easy to imitate. Check an order through the company’s known app or type its address yourself.',
  },
  {
    id: 'coworker-gift-card',
    sender: 'A saved contact',
    channel: 'CHAT MESSAGE · FICTIONAL EXAMPLE',
    message: 'I’m in a meeting. Can you buy two gift cards right now and send me the codes? I’ll pay you back.',
    clue: 'The request is rushed and asks for a payment method that is hard to reverse.',
    choices: [
      { text: 'Buy the cards and send the codes as requested.', safe: false },
      { text: 'Call the person on a number I already know before doing anything.', safe: true },
      { text: 'Ask the sender to confirm the request in the same chat.', safe: false },
    ],
    explanation: 'A familiar name or account can be impersonated. Verify through a separate trusted channel before sending money or gift-card codes.',
  },
  {
    id: 'password-support',
    sender: 'Account Help',
    channel: 'EMAIL · FICTIONAL EXAMPLE',
    message: 'Our support team needs your password to prevent a temporary account restriction. Reply today.',
    clue: 'A support representative is asking for a password and pressuring you to act.',
    choices: [
      { text: 'Reply with my password so support can help.', safe: false },
      { text: 'Do not reply; contact support through the official app or site.', safe: true },
      { text: 'Send a password-reset code instead of my password.', safe: false },
    ],
    explanation: 'Legitimate support should never ask for your password or verification code. Contact the service through a channel you navigate to yourself.',
  },
  {
    id: 'routine-update',
    sender: 'GreenCart (fictional app)',
    channel: 'APP NOTIFICATION · FICTIONAL EXAMPLE',
    message: 'Your weekly order summary is ready. Open the GreenCart app to review it. No reply is needed.',
    clue: 'This notice does not ask for a code, payment, or urgent action, and it directs you to open an app you already use.',
    choices: [
      { text: 'Open the app from my home screen if I want to check the summary.', safe: true },
      { text: 'Reply with my password to confirm I received it.', safe: false },
      { text: 'Treat any message mentioning an order as definitely fraudulent.', safe: false },
    ],
    explanation: 'Not every notification is a scam. A calm update with no credential or payment request may be routine, but you can still open the app independently instead of trusting a message link.',
  },
];

function shufflePracticeIds() {
  return practiceScenarios.map((scenario) => scenario.id).sort(() => Math.random() - 0.5);
}

function PracticePage() {
  const [scenarioIds, setScenarioIds] = useState(shufflePracticeIds);
  const [index, setIndex] = useState(0);
  const [choice, setChoice] = useState<number | null>(null);
  const [showClue, setShowClue] = useState(false);
  const [correctCount, setCorrectCount] = useState(0);
  const scenario = practiceScenarios.find((item) => item.id === scenarioIds[index]);
  const finished = index >= scenarioIds.length;

  function startNewSet() {
    setScenarioIds(shufflePracticeIds());
    setIndex(0);
    setChoice(null);
    setShowClue(false);
    setCorrectCount(0);
  }

  function advance() {
    setIndex((current) => current + 1);
    setChoice(null);
    setShowClue(false);
  }

  return <div className="page-wrap">
    <PageHeading eyebrow="PRACTICE ROOM" title="Build confidence by practicing." description="Work through fictional situations and decide how you would respond."/>
    <div className="practice-disclaimer"><Info size={16}/><span>These are fictional practice scenarios, not live threats. Nothing you type here is sent or saved.</span></div>
    {finished ? <Card className="practice-finish">
      <div className="practice-finish-mark"><Check size={27}/></div><div className="eyebrow">SET COMPLETE</div>
      <h2>You made it through the practice set.</h2><p>You chose a safer response in <strong>{correctCount} of {scenarioIds.length}</strong> scenarios. Use the explanations as guidance—not as a test of perfection.</p>
      <Button className="submit-button" onClick={startNewSet} data-testid="button-practice-again"><RotateCcw size={16}/>Try another set</Button>
    </Card> : scenario ? <div className="practice-workspace">
      <Card className="practice-card">
        <div className="practice-progress-head"><span>SCENARIO {index + 1} OF {scenarioIds.length}</span><span>{correctCount} safer choices</span></div>
        <div className="practice-progress"><span style={{ width: `${((index + 1) / scenarioIds.length) * 100}%` }}/></div>
        <div className="practice-message-meta"><span className="practice-message-icon"><MessageSquareText size={18}/></span><span><strong>{scenario.sender}</strong><small>{scenario.channel}</small></span><span className="fictional-stamp">FICTIONAL</span></div>
        <blockquote className="practice-message" data-testid={`text-practice-message-${scenario.id}`}>{scenario.message}</blockquote>
        <button type="button" className="clue-button" onClick={() => setShowClue((visible) => !visible)} data-testid="button-practice-clue"><Lightbulb size={16}/>{showClue ? 'Hide clue' : 'Show me a clue'}</button>
        {showClue && <div className="practice-clue" data-testid="text-practice-clue">{scenario.clue}</div>}
        <div className="practice-question"><div className="eyebrow">WHAT WOULD YOU DO?</div><div className="practice-choices">
          {scenario.choices.map((item, optionIndex) => <button type="button" className={`practice-choice ${choice === optionIndex ? (item.safe ? 'selected-safe' : 'selected-unsafe') : ''}`} key={item.text} disabled={choice !== null} onClick={() => { setChoice(optionIndex); if (item.safe) setCorrectCount((current) => current + 1); }} data-testid={`button-practice-choice-${scenario.id}-${optionIndex}`}><span className="choice-letter">{String.fromCharCode(65 + optionIndex)}</span><span>{item.text}</span>{choice === optionIndex && (item.safe ? <Check size={17}/> : <X size={17}/>)}</button>)}
        </div></div>
        {choice !== null && <div className={`practice-feedback ${scenario.choices[choice].safe ? 'right' : ''}`} role="status" data-testid="status-practice-feedback"><strong>{scenario.choices[choice].safe ? 'That is a safer choice.' : 'Pause and try a safer route next time.'}</strong><p>{scenario.explanation}</p></div>}
        {choice !== null && <Button className="submit-button practice-next" onClick={advance} data-testid="button-practice-next">{index === scenarioIds.length - 1 ? 'See your summary' : 'Next scenario'} <ArrowRight size={16}/></Button>}
      </Card>
      <aside className="practice-side"><span className="practice-side-icon"><ShieldCheck size={20}/></span><div className="eyebrow">A SIMPLE RULE</div><h2>Pause. Check another way. Protect your details.</h2><p>Real messages can be legitimate or fraudulent. When a request feels unexpected, verify it through an app, website, or contact detail you already trust.</p><Link href="/learn" className="text-link" data-testid="link-practice-lessons">Review the lessons <ArrowRight size={14}/></Link></aside>
    </div> : null}
  </div>;
}

function LoginPage() {
  const { authConfigured, authReady, authError, clearAuthError, user, signIn, register, logOut } = useApp();
  const [mode, setMode] = useState<'signin' | 'register'>('signin');
  const form = useForm<{ email: string; password: string }>({
    resolver: zodResolver(z.object({
      email: z.string().email('Enter a valid email address.'),
      password: z.string().min(6, 'Password must be at least 6 characters.'),
    })),
    defaultValues: { email: '', password: '' },
  });
  const submit = form.handleSubmit(async ({ email, password }) => {
    clearAuthError();
    try {
      if (mode === 'signin') await signIn(email.trim(), password);
      else await register(email.trim(), password);
    } catch {
      // The Firebase auth hook exposes a user-facing error message.
    }
  });

  return <div className="page-wrap">
    <PageHeading eyebrow="ACCOUNT" title="Your space, your choice." description={user ? 'Your private scan history is connected to this account.' : 'Scanning and learning work without an account.'}/>
    <div className="account-layout">
      <Card className="account-card">
        <div className="account-lock"><LockKeyhole size={22}/></div>
        {user ? <>
          <h2>You’re signed in</h2>
          <p>{user.email}</p>
          <div className="setup-notice"><ShieldCheck size={17}/><span><strong>Firebase account active</strong> Your scan metadata and saved lesson progress use your account.</span></div>
          {authError && <div className="form-error" role="alert" data-testid="status-auth-error">{authError}</div>}
          <Button type="button" variant="outline" className="submit-button" onClick={() => void logOut().catch(() => {})} disabled={!authReady} data-testid="button-logout">Sign out <ArrowRight size={16}/></Button>
        </> : <>
          <h2>{authConfigured ? (mode === 'signin' ? 'Welcome back.' : 'Create your account.') : 'Sign in when it’s ready'}</h2>
          <p>{authConfigured ? 'Your history stays private to your signed-in account.' : 'Email and password sign-in becomes available after Firebase project setup.'}</p>
          {!authConfigured && <div className="setup-notice"><Info size={17}/><span><strong>Setup needed</strong> Firebase is not configured. No credentials are collected or validated on this screen.</span></div>}
          {authConfigured && <>
            {authError && <div className="form-error" role="alert" data-testid="status-auth-error">{authError}</div>}
            <Form {...form}><form className="form-stack account-form" onSubmit={submit}>
              <FormField control={form.control} name="email" render={({ field }) => <FormItem><FormLabel>Email address</FormLabel><FormControl><Input {...field} type="email" placeholder="you@example.com" autoComplete="email" data-testid="input-login-email"/></FormControl><FormMessage/></FormItem>}/>
              <FormField control={form.control} name="password" render={({ field }) => <FormItem><FormLabel>Password</FormLabel><FormControl><Input {...field} type="password" placeholder="At least 6 characters" autoComplete={mode === 'signin' ? 'current-password' : 'new-password'} data-testid="input-login-password"/></FormControl><FormMessage/></FormItem>}/>
              <Button type="submit" disabled={!authReady} className="submit-button" data-testid="button-login">{mode === 'signin' ? 'Sign in' : 'Create account'} <ArrowRight size={16}/></Button>
            </form></Form>
            <button type="button" className="text-link account-mode-toggle" onClick={() => { setMode(mode === 'signin' ? 'register' : 'signin'); clearAuthError(); }} data-testid="button-toggle-auth-mode">{mode === 'signin' ? 'New here? Create an account' : 'Already registered? Sign in'}</button>
          </>}
        </>}
        <div className="account-local"><ShieldCheck size={16}/>You can scan and learn without signing in.</div>
      </Card>
      <div className="account-aside"><div className="eyebrow">PRIVACY FIRST</div><h2>Start with what you have.</h2><p>{user ? 'Only scan metadata is kept in your cloud history. Submitted message text and full link paths are not stored.' : 'Without an account, your scan history stays locally in this browser. Add Firebase configuration to enable private cloud sync.'}</p><Link href="/scan/url" className="text-link" data-testid="link-account-scan">Start a check <ArrowRight size={15}/></Link><div className="account-line"/></div>
    </div>
  </div>;
}
function SettingsPage() {
  const { language, setLanguage, clearHistory, history, historySource, historyError, authConfigured, user } = useApp(); const [cleared, setCleared] = useState(false);
  return <div className="page-wrap"><PageHeading eyebrow="PREFERENCES" title="Settings" description="Make CyberShield feel comfortable for you."/><div className="settings-stack"><Card className="settings-card"><div className="settings-leading"><span className="settings-icon"><Languages size={19}/></span><div><h2>Language</h2><p>Language choice is used for scans and supported interface copy. It is not an AI translation.</p></div></div><div className="language-options">{([{code:'en',label:'English',native:'English'}, {code:'hi',label:'Hindi',native:'हिन्दी'}, {code:'te',label:'Telugu',native:'తెలుగు'}] as const).map(item => <button key={item.code} className={`language-option ${language === item.code ? 'chosen' : ''}`} onClick={() => setLanguage(item.code)} data-testid={`button-language-${item.code}`}><span className="language-radio">{language === item.code && <span/>}</span><span><strong>{item.label}</strong><small>{item.native}</small></span>{language === item.code && <Check size={16}/>}</button>)}</div></Card>
      <Card className="settings-card"><div className="settings-leading"><span className="settings-icon"><LockKeyhole size={19}/></span><div><h2>Privacy controls</h2><p>{historySource === 'cloud' ? 'Your metadata-only history is connected to your Firebase account.' : 'Your scan history remains in local browser storage.'}</p></div></div><div className="privacy-details"><div><strong>Account</strong><span>{user?.email || (authConfigured ? 'Firebase is configured; sign-in is optional' : 'Firebase setup required for email/password sign-in')}</span></div><div><strong>History retention</strong><span>{historySource === 'cloud' ? 'Saved in your account' : 'Saved on this device only'}</span></div><div><strong>Stored details</strong><span>Hostname only for links; never full URL paths or message text</span></div><div><strong>Clear scan history</strong><span>Remove all saved metadata from {historySource === 'cloud' ? 'your account' : 'this browser'}</span></div>{historyError && <div className="form-error" role="alert" data-testid="status-settings-error">{historyError}</div>}<Button variant="outline" className="settings-clear" disabled={!history.length} onClick={() => { clearHistory(); setCleared(true); }} data-testid="button-settings-clear"><Trash2 size={15}/>{cleared ? 'History cleared' : `Clear ${historySource === 'cloud' ? 'cloud' : 'local'} history`}</Button>{!user && <Link href="/login" className="text-link" data-testid="link-settings-account">Account setup and sign in <ArrowRight size={15}/></Link>}</div></Card>
      <div className="settings-note"><ShieldCheck size={17}/><span><strong>Understand the limits.</strong> This rule-based analyzer does not visit links and does not check live threat feeds. Results are guidance, not a guarantee.</span></div>
    </div></div>;
}
export default App;

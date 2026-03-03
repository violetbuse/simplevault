import { useState } from "react";
import { BrowserRouter, Routes, Route, Link, useLocation } from "react-router-dom";
import ConfigDoc from "./pages/ConfigDoc";
import ApiDoc from "./pages/ApiDoc";
import ConfigMaker from "./pages/ConfigMaker";
import DevDoc from "./pages/DevDoc";

const navLinks = [
  { to: "/", label: "Config" },
  { to: "/config-maker", label: "Config Maker" },
  { to: "/api", label: "API Routes" },
  { to: "/dev", label: "Client & Dev" },
];

function NavLinks({
  location,
  onNavigate,
}: {
  location: ReturnType<typeof useLocation>;
  onNavigate?: () => void;
}) {
  return (
    <>
      {navLinks.map(({ to, label }) => (
        <Link
          key={to}
          to={to}
          onClick={onNavigate}
          className={`block px-3 py-2 rounded-lg transition-colors ${
            location.pathname === to
              ? "bg-[var(--accent)]/20 text-[var(--accent)]"
              : "text-[var(--text-muted)] hover:text-[var(--text)] hover:bg-white/5"
          }`}
        >
          {label}
        </Link>
      ))}
    </>
  );
}

function Layout() {
  const location = useLocation();
  const [menuOpen, setMenuOpen] = useState(false);

  return (
    <div className="min-h-screen flex flex-col md:flex-row">
      {/* Mobile header */}
      <header className="md:hidden flex items-center justify-between px-4 py-3 border-b border-[var(--border)] bg-[var(--surface-elevated)] shrink-0">
        <Link
          to="/"
          className="text-lg font-semibold text-[var(--accent)]"
          onClick={() => setMenuOpen(false)}
        >
          SimpleVault
        </Link>
        <button
          type="button"
          onClick={() => setMenuOpen((o) => !o)}
          className="p-2 rounded-lg text-[var(--text-muted)] hover:text-[var(--text)] hover:bg-white/5"
          aria-label="Toggle menu"
        >
          <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            {menuOpen ? (
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            ) : (
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
            )}
          </svg>
        </button>
      </header>

      {/* Mobile menu overlay */}
      {menuOpen && (
        <div
          className="md:hidden fixed inset-0 z-40 bg-black/60"
          onClick={() => setMenuOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Sidebar: overlay on mobile, fixed on desktop */}
      <aside
        className={`
          fixed top-0 left-0 z-50
          h-screen w-64 md:w-56
          border-r border-[var(--border)] bg-[var(--surface-elevated)]
          p-6 flex flex-col gap-2 overflow-y-auto
          transform transition-transform duration-200 ease-out
          md:transform-none md:translate-x-0
          ${menuOpen ? "translate-x-0" : "-translate-x-full"}
        `}
      >
        <Link
          to="/"
          className="text-lg font-semibold text-[var(--accent)] hover:text-[var(--accent-muted)] transition-colors"
          onClick={() => setMenuOpen(false)}
        >
          SimpleVault
        </Link>
        <nav className="mt-6 flex flex-col gap-1">
          <NavLinks location={location} onNavigate={() => setMenuOpen(false)} />
        </nav>
      </aside>

      <main className="flex-1 p-4 sm:p-6 md:p-12 max-w-3xl w-full min-w-0 md:ml-56">
        <Routes>
          <Route path="/" element={<ConfigDoc />} />
          <Route path="/config-maker" element={<ConfigMaker />} />
          <Route path="/api" element={<ApiDoc />} />
          <Route path="/dev" element={<DevDoc />} />
        </Routes>
      </main>
    </div>
  );
}

function App() {
  return (
    <BrowserRouter>
      <Layout />
    </BrowserRouter>
  );
}

export default App;

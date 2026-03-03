export default function Home() {
  const links = [
    {
      title: "Releases (built binaries)",
      description: "Pre-built server binaries for Linux",
      href: "https://github.com/violetbuse/simplevault/releases",
      label: "GitHub Releases",
    },
    {
      title: "Docker image",
      description: "Run SimpleVault server in a container",
      href: "https://github.com/users/violetbuse/packages/container/package/simplevault",
      label: "GitHub Container Registry",
    },
    {
      title: "Client library & dev server",
      description: "npm package for the JavaScript client and local dev server",
      href: "https://www.npmjs.com/package/simplevault",
      label: "npm — simplevault",
    },
    {
      title: "Source code",
      description: "Rust server, React client, and documentation",
      href: "https://github.com/violetbuse/simplevault",
      label: "GitHub — violetbuse/simplevault",
    },
  ];

  return (
    <article className="prose prose-invert max-w-none">
      <h1 className="text-3xl font-bold mb-2">SimpleVault</h1>
      <p className="text-[var(--text-muted)] mb-10">
        Documentation and quick links for the SimpleVault encryption vault server and client.
      </p>

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-4 text-[var(--accent)]">Quick links</h2>
        <ul className="space-y-4 list-none p-0 m-0">
          {links.map(({ title, description, href, label }) => (
            <li key={href} className="border border-[var(--border)] rounded-lg overflow-hidden bg-[var(--surface-elevated)]">
              <a
                href={href}
                target="_blank"
                rel="noopener noreferrer"
                className="block p-5 hover:bg-white/5 transition-colors group"
              >
                <h3 className="font-semibold text-[var(--accent)] group-hover:text-[var(--accent-muted)] transition-colors mb-1">
                  {title}
                </h3>
                <p className="text-sm text-[var(--text-muted)] mb-2">{description}</p>
                <span className="text-sm font-mono text-[var(--text-muted)] group-hover:text-[var(--text)]">
                  {label} →
                </span>
              </a>
            </li>
          ))}
        </ul>
      </section>

      <p className="text-sm text-[var(--text-muted)]">
        Use the sidebar to read about configuration, the API, and the client & dev server.
      </p>
    </article>
  );
}

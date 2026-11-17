"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";

import { API_BASE, health } from "@/lib/api";

const LINKS = [
  { href: "/", label: "Scanner" },
  { href: "/admin", label: "Dashboard" },
];

export function Logo({ size = 26 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden="true">
      <defs>
        <linearGradient id="pg-logo" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#38bdf8" />
          <stop offset="1" stopColor="#6366f1" />
        </linearGradient>
      </defs>
      <path d="M32 4 L54 11 Q57 12 57 15 L57 30 Q57 49 32 60 Q7 49 7 30 L7 15 Q7 12 10 11 Z" fill="url(#pg-logo)" />
      <path d="M20 32 L28 40 L44 23" fill="none" stroke="#fff" strokeWidth="5.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export default function Nav() {
  const pathname = usePathname();
  const [online, setOnline] = useState<boolean | null>(null);

  useEffect(() => {
    let alive = true;
    const check = () => health().then((ok) => alive && setOnline(ok));
    check();
    const timer = setInterval(check, 15_000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, []);

  return (
    <header className="sticky top-0 z-20 border-b border-line/70 bg-page/80 backdrop-blur">
      <div className="mx-auto flex h-14 w-full max-w-6xl items-center gap-6 px-4 sm:px-6">
        <Link href="/" className="flex items-center gap-2 font-semibold tracking-tight">
          <Logo />
          PhishGuard
        </Link>
        <nav className="flex gap-1 text-sm">
          {LINKS.map((link) => {
            const active = link.href === "/" ? pathname === "/" : pathname.startsWith(link.href);
            return (
              <Link
                key={link.href}
                href={link.href}
                className={`rounded-lg px-3 py-1.5 transition-colors ${
                  active ? "bg-raised text-ink" : "text-muted hover:text-ink"
                }`}
              >
                {link.label}
              </Link>
            );
          })}
        </nav>
        <div className="ml-auto flex items-center gap-2 text-xs text-muted" title={API_BASE}>
          <span
            className="h-2 w-2 rounded-full"
            style={{ background: online == null ? "var(--color-muted)" : online ? "var(--color-good)" : "var(--color-critical)" }}
          />
          <span className="hidden sm:inline">{online == null ? "Checking API" : online ? "API online" : "API offline"}</span>
        </div>
      </div>
    </header>
  );
}

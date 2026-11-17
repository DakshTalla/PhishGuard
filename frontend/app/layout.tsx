import type { Metadata } from "next";

import Nav from "@/components/Nav";
import "./globals.css";

export const metadata: Metadata = {
  title: "PhishGuard",
  description: "Phishing and malicious URL detection with explainable scores.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className="antialiased">
      <body className="min-h-screen font-sans">
        <Nav />
        <main className="mx-auto w-full max-w-6xl px-4 pb-16 sm:px-6">{children}</main>
      </body>
    </html>
  );
}

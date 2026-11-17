import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  devIndicators: false, // the floating dev badge would cover the result panel in screenshots
  agentRules: false,    // do not generate an AGENTS.md for AI coding tools in this repo
};

export default nextConfig;

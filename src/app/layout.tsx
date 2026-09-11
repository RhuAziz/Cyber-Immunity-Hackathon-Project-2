import type { Metadata } from "next";
import { Providers } from "./providers";
import { Nav } from "./nav";
import "./globals.css";

export const metadata: Metadata = {
  title: "Hospital Emergency Platform",
  description:
    "Emergency alerting and incident reporting with TideCloak policy-governed encryption",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Providers>
          <Nav />
          <main id="main" className="container">
            {children}
          </main>
        </Providers>
      </body>
    </html>
  );
}

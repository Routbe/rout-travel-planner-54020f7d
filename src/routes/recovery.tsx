import { createFileRoute } from "@tanstack/react-router";
import { RecoveryLogin } from "@/components/recovery/RecoveryLogin";

export const Route = createFileRoute("/recovery")({
  head: () => ({
    meta: [
      { title: "Inloggen met herstel | ROUT" },
      { name: "description", content: "Buitengesloten? Log in met 2 van je 3 herstelstukken en krijg je ROUT-hoofdsleutel terug." },
      { property: "og:title", content: "Inloggen met herstel | ROUT" },
      { property: "og:description", content: "Herstel je ROUT-account met 2 van je 3 stukken." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
      { name: "robots", content: "noindex, nofollow" },
      { name: "referrer", content: "no-referrer" },
    ],
  }),
  component: RecoveryLogin,
});

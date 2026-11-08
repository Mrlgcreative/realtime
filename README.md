# realtime

Mixify temps réel (Fly.io)

Serveur WebSocket (salle par compte) pour le playback, la connexion QR,
les notifications et le suivi d'abonnement. Les clients (front + mobile)
utilisent ce canal en priorité, avec le long-poll Vercel /api/realtime en plan B.

- Node >= 20, dépendance unique: ws
- Auth: JWT HS256 du backend (JWT_SECRET) ou pollToken anonyme (canal login)
- Secrets via  — jamais dans git

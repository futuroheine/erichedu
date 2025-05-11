const CACHE_NAME = 'aviso-cache-v1';

self.addEventListener('install', event => {
    self.skipWaiting(); // instala imediatamente
    event.waitUntil(caches.open(CACHE_NAME));
});

self.addEventListener('activate', event => {
    event.waitUntil(clients.claim()); // assume controle das abas
});

// Este evento escuta mensagens de páginas
self.addEventListener('message', event => {
    const data = event.data;
    if (data.type === 'SHOW_NOTIFICATION') {
        self.registration.showNotification(data.title, {
            body: data.body,
            icon: '/static/icons/bell.png', // pode usar ícone personalizado
        });
    }
});

// Ouvindo o evento de push para exibir notificações quando recebidas
self.addEventListener('push', event => {
    const data = event.data.json();
    const title = data.title || 'Novo Aviso';
    const options = {
        body: data.message,
        icon: '/static/icons/bell.png', // ícone da notificação
        badge: '/static/icons/badge.png', // badge (opcional)
    };

    event.waitUntil(self.registration.showNotification(title, options));
});

// Redirecionar ao clicar na notificação
self.addEventListener('notificationclick', event => {
    event.notification.close();
    event.waitUntil(
        clients.openWindow('/home') // Redireciona para a página de avisos
    );
});

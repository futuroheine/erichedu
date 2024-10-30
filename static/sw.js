// sw.js

self.addEventListener('push', function(event) {
    const data = event.data.json();

    // Opções de notificação
    const options = {
        body: data.message,
        icon: data.foto_perfil || 'default-avatar.png',  // Ícone da notificação
        badge: 'default-badge.png'  // Opcional: um ícone pequeno para o badge
    };

    // Exibe a notificação
    event.waitUntil(
        self.registration.showNotification(data.user_nome, options)
    );
});

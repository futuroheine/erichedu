const CACHE_NAME = 'aviso-cache-v1';

// Variáveis para armazenar o tempo do último aviso
let ultimoAviso = Date.now();

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

// Verificar periodicamente por novos avisos no servidor
setInterval(async () => {
    // Obter a turma do usuário (exemplo: armazenado em localStorage ou de outra forma)
    const turmaId = localStorage.getItem('turmaId'); // Aqui você pode pegar a turma de outra forma, se necessário.

    if (!turmaId) {
        console.log('Turma não encontrada');
        return;
    }

    // Requisição para o servidor para buscar novos avisos para a turma
    const response = await fetch(`/api/novos-avisos/${turmaId}`);

    if (response.ok) {
        const data = await response.json();

        // Verifique se há novos avisos
        const novosAvisos = data.avisos.filter(aviso => new Date(aviso.timestamp).getTime() > ultimoAviso);

        if (novosAvisos.length > 0) {
            // Atualiza o tempo do último aviso para evitar notificações duplicadas
            ultimoAviso = Date.now();

            // Mostra as notificações para os novos avisos
            novosAvisos.forEach(aviso => {
                self.registration.showNotification(aviso.titulo, {
                    body: aviso.mensagem,
                    icon: '/static/icons/bell.png', // ícone da notificação
                    badge: '/static/icons/badge.png', // badge (opcional)
                });
            });
        }
    } else {
        console.error('Erro ao buscar novos avisos:', response.status);
    }
}, 1000); // Verifica a cada 1 segundo

// Redirecionar ao clicar na notificação
self.addEventListener('notificationclick', event => {
    event.notification.close();
    event.waitUntil(
        clients.openWindow('/home') // Redireciona para a página de avisos
    );
});

const CACHE_NAME = 'aviso-cache-v1';

// Variáveis para armazenar o tempo do último aviso
let ultimoAviso = Date.now();
let turmaId = null; // Variável para armazenar a turmaId

// Verificar se o setInterval já foi iniciado
let intervaloVerificacao = null;

self.addEventListener('install', event => {
    console.log('Service Worker instalado');
    self.skipWaiting(); // instala imediatamente
    event.waitUntil(caches.open(CACHE_NAME));
});

self.addEventListener('activate', event => {
    console.log('Service Worker ativado');
    event.waitUntil(clients.claim()); // assume controle das abas
});

// Este evento escuta mensagens de páginas
self.addEventListener('message', event => {
    const data = event.data;
    
    // Recebe a turmaId e inicia a verificação de novos avisos
    if (data.type === 'SET_TURMA_ID') {
        turmaId = data.turmaId;
        console.log('Turma ID recebida no Service Worker:', turmaId);
        
        // Inicia a verificação se ainda não foi iniciada
        if (turmaId && !intervaloVerificacao) {
            intervaloVerificacao = setInterval(async () => {
                // Verificar por novos avisos a cada 10 segundos
                if (!turmaId) {
                    console.log('Turma não encontrada');
                    return;
                }

                const response = await fetch(`/api/novos-avisos/${turmaId}`);
                if (response.ok) {
                    const data = await response.json();

                    // Filtra os novos avisos que são posteriores ao último aviso
                    const novosAvisos = data.avisos.filter(aviso => new Date(aviso.timestamp).getTime() > ultimoAviso);

                    if (novosAvisos.length > 0) {
                        // Atualiza o tempo do último aviso para evitar notificações duplicadas
                        ultimoAviso = Date.now();

                        // Mostra as notificações para os novos avisos
                        novosAvisos.forEach(aviso => {
                            self.registration.showNotification(aviso.titulo, {
                                body: aviso.mensagem,
                                icon: '/static/icons/bell.png',
                                badge: '/static/erichedu-icon.png',
                            });
                        });
                    }
                } else {
                    console.error('Erro ao buscar novos avisos:', response.status);
                }
            }, 10000); // Verifica a cada 10 segundos
        }
    }

    if (data.type === 'SHOW_NOTIFICATION') {
        self.registration.showNotification(data.title, {
            body: data.body,
            icon: '/static/icons/bell.png', // ícone da notificação
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
        badge: '/static/erichedu-icon.png', // badge (opcional)
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

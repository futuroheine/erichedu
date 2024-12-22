from flask import Flask, render_template, request, jsonify
import requests

app = Flask(__name__)

# Defina a URL do servidor Matrix
MATRIX_SERVER_URL = "https://matrix.org"  # Substitua pelo seu servidor Matrix
ACCESS_TOKEN = "syt_YW5kcmV3eHJrMzAwOQ_pXeMRQmjMhyUFYVAPapy_4LxWv2"  # O token de acesso fornecido
USER_ID = "@seu_usuario:matrix.org"  # Substitua pelo seu ID de usuário no Matrix
ROOM_ID = "!eGokYNrahuegeJyGcC:matrix.org"  # Substitua pelo ID do chat/room

# Rota principal para o chat (exibe a página HTML do chat)
@app.route('/chat')
def chat():
    # Obter o histórico de mensagens
    messages = get_message_history()

    # Renderiza a página HTML do chat e passa as mensagens
    return render_template('chat.html', messages=messages)

# Função para obter o histórico de mensagens do Matrix
def get_message_history():
    url = f"{MATRIX_SERVER_URL}/_matrix/client/r0/rooms/{ROOM_ID}/messages"
    
    headers = {
        "Authorization": f"Bearer {ACCESS_TOKEN}",
    }

    # Definindo o limite de mensagens que queremos trazer
    params = {
        "limit": 10  # Limite de mensagens a serem buscadas
    }

    response = requests.get(url, params=params, headers=headers)
    if response.status_code == 200:
        messages = response.json().get('chunk', [])
        formatted_messages = []

        for msg in messages:
            formatted_message = {
                "sender": msg['sender'],
                "timestamp": msg['origin_server_ts'],
            }

            # Verificar se o tipo da mensagem é texto e tem um corpo
            if 'body' in msg['content']:
                formatted_message["body"] = msg['content']['body']
            else:
                formatted_message["body"] = "(Mensagem sem conteúdo de texto)"  # Caso não tenha 'body'

            # Obter foto de perfil do remetente
            profile_url = f"{MATRIX_SERVER_URL}/_matrix/client/r0/profile/{msg['sender']}"
            profile_response = requests.get(profile_url, headers=headers)
            if profile_response.status_code == 200:
                profile_data = profile_response.json()
                formatted_message["avatar_url"] = profile_data.get('avatar_url', '')
            else:
                formatted_message["avatar_url"] = ''

            formatted_messages.append(formatted_message)
        return formatted_messages
    else:
        return []

# Rota para enviar mensagens
@app.route('/send_message', methods=['POST'])
def send_message():
    # Receber a mensagem do frontend
    data = request.json
    message = data.get('message', '')

    if message:
        # Enviar a mensagem para o servidor Matrix
        response = send_message_to_matrix(message)
        if response.status_code == 200:
            return jsonify({"status": "success", "message": "Mensagem enviada com sucesso!"}), 200
        else:
            return jsonify({"status": "error", "message": "Erro ao enviar mensagem para o servidor Matrix."}), 500
    else:
        return jsonify({"status": "error", "message": "Mensagem não pode ser vazia."}), 400

# Função para enviar a mensagem via API do Matrix
def send_message_to_matrix(message):
    url = f"{MATRIX_SERVER_URL}/_matrix/client/r0/rooms/{ROOM_ID}/send/m.room.message"
    
    headers = {
        "Authorization": f"Bearer {ACCESS_TOKEN}",
        "Content-Type": "application/json"
    }

    data = {
        "msgtype": "m.text",  # Tipo de mensagem (texto)
        "body": message      # O corpo da mensagem
    }

    response = requests.post(url, json=data, headers=headers)
    return response

if __name__ == '__main__':
    app.run(debug=True)

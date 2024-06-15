<?php
session_start(); // Inicia a sessão

require_once 'conexao.php';

$errors = [
    'email' => '',
    'password' => '',
    'general' => ''
];

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);

    // Validação no servidor
    if (empty($email)) {
        $errors['email'] = "O campo de e-mail é obrigatório.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors['email'] = "Por favor, insira um endereço de e-mail válido.";
    }

    if (empty($password)) {
        $errors['password'] = "O campo de senha é obrigatório.";
    }

    if (empty(array_filter($errors))) {
        // Verificar se o email existe no banco de dados
        $sql = "SELECT * FROM users WHERE email = ?";
        $stmt = $conexao->prepare($sql);

        if ($stmt === false) {
            $errors['general'] = "Erro ao preparar a consulta: " . $conexao->error;
        } else {
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result->num_rows > 0) {
                $user = $result->fetch_assoc();
                // Verificar a senha
                if (password_verify($password, $user['password'])) {
                    // Login bem-sucedido
                    $_SESSION['user_id'] = $user['user_id'];
                    $_SESSION['email'] = $user['email'];
                    $redirect_url = "userLogado.html"; // URL da página para onde quer redirecionar
                    echo json_encode(['success' => true, 'redirect' => $redirect_url]);            
                   exit();
                } else {
                    // Senha incorreta
                    $errors['password'] = "Senha incorreta.";
                }
            } else {
                // Email não encontrado
                $errors['email'] = "E-mail não encontrado.";
            }

            $stmt->close();
        }
    } else {
        $errors['general'] = "Por favor, corrija os erros abaixo.";
    }

    $conexao->close();
}

echo json_encode(['success' => false, 'errors' => $errors]);
?>

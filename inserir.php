<?php
require_once 'conexao.php';

$errors = [
    'username' => '',
    'email' => '',
    'password' => '',
    'general' => ''
];

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);

    // Validação no servidor
    if (empty($username)) {
        $errors['username'] = "O campo de nome de usuário é obrigatório.";
    } elseif (strlen($username) < 3) {
        $errors['username'] = "O nome de usuário deve ter pelo menos 3 caracteres.";
    }

    if (empty($email)) {
        $errors['email'] = "O campo de e-mail é obrigatório.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors['email'] = "Por favor, insira um endereço de e-mail válido.";
    }

    if (empty($password)) {
        $errors['password'] = "O campo de senha é obrigatório.";
    }

    if (empty(array_filter($errors))) {
        // Verificar se o e-mail já está cadastrado
        $sql = "SELECT email FROM users WHERE email = ?";
        $stmt = $conexao->prepare($sql);
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            $errors['email'] = "Este e-mail já está cadastrado.";
        } else {
            // Verificar se o nome de usuário já está cadastrado
            $stmt->close();
            $sql = "SELECT username FROM users WHERE username = ?";
            $stmt = $conexao->prepare($sql);
            $stmt->bind_param("s", $username);
            $stmt->execute();
            $stmt->store_result();

            if ($stmt->num_rows > 0) {
                $errors['username'] = "Este nome de usuário já está cadastrado.";
            } else {
                // Inserir novo usuário
                $stmt->close();
                
                $passwordHash = password_hash($password, PASSWORD_BCRYPT);

                $sql = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)";
                $stmt = $conexao->prepare($sql);
                $stmt->bind_param("sss", $username, $email, $passwordHash);

                if ($stmt->execute()) {
                    $redirect_url = "userCadastrado.html"; // Substitua pela página desejada
                    echo json_encode(['success' => true, 'redirect' => $redirect_url]);
                    exit();
                } else {
                    $errors['general'] = "Erro ao cadastrar: " . $stmt->error;
                }
            }
        }

        $stmt->close();
    }

    $conexao->close();
}

echo json_encode(['success' => false, 'errors' => $errors]);
?>
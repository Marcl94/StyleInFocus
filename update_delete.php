<?php
require_once 'conexao.php';

session_start();

if (!isset($_SESSION['username'])) {
    header("Location: login.php");
    exit();
}

$username = $_SESSION['username'];

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (isset($_POST['update'])) {
        $newPassword = trim($_POST['new_password']);

        if (!empty($newPassword)) {
            $newPasswordHash = password_hash($newPassword, PASSWORD_BCRYPT);
            $stmt = $conexao->prepare('UPDATE users SET password = ? WHERE username = ?');
            $stmt->bind_param('ss', $newPasswordHash, $username);

            if ($stmt->execute()) {
                header("Location: userUpdate.html");
                exit();
            } else {
                echo "Erro ao atualizar senha: " . $stmt->error;
            }

            $stmt->close();
        } else {
            echo "A nova senha não pode estar vazia.";
        }
    }

    if (isset($_POST['delete'])) {
        $stmt = $conexao->prepare('DELETE FROM users WHERE username = ?');
        $stmt->bind_param('s', $username);

        if ($stmt->execute()) {
            session_destroy();
            header("Location: index.html");
            exit();
        } else {
            echo "Erro ao excluir conta: " . $stmt->error;
        }

        $stmt->close();
    }
}

$conexao->close();
?>

// Função para pegar o elemento pelo ID
let $id = id => document.getElementById(id);

// Pegando os elementos de login, registro e formulário
var [login, register, form] = ['login', 'register', 'form'].map(id => $id(id));

// Alternar entre os formulários de login e registro
[login, register].map(element => {
  element.onclick = function () {
    // Remove a classe "active" dos dois botões
    [login, register].map($ele => {
      $ele.classList.remove("active");
    });
    // Adiciona a classe "active" ao botão clicado
    this.classList.add("active");

    // Verifica se o botão clicado é o de registro
    this.getAttribute("id") === "register" ? form.classList.add("active") : form.classList.remove("active");
  };
});

// Função para mostrar mensagens de alerta para o usuário
function showMessage(message, isSuccess = false) {
  alert(message); // Exibe um alerta com a mensagem
}

// Função assíncrona que envia o formulário para a API
async function sendForm(endpoint, data) {
  try {
    const response = await fetch(`projetojwt-back-end-production.up.railway.app/auth/${endpoint}`, {
      method: 'POST', // Define o método como POST
      headers: {
        'Content-Type': 'application/json' // Define o tipo de conteúdo como JSON
      },
      body: JSON.stringify(data), // Converte os dados para JSON
      mode: 'cors', // Adicionado para garantir que CORS esteja ativado
    });

    // Verifica se a API respondeu com sucesso
    if (response.ok) {
      const result = await response.json();

      if (endpoint === 'login') {
        // Se for login, armazena o token e o nome do usuário no localStorage
        localStorage.setItem('token', result.token); // Armazena o token de autenticação
        localStorage.setItem('userName', result.name); // Armazena o nome do usuário

        // Redireciona o usuário para a página principal
        window.location.href = 'login.html';
      }

      // Exibe uma mensagem de sucesso
      showMessage(result.msg || result.message || 'Operação realizada com sucesso!', true); 
      console.log(result); // Exibe o resultado da API no console

    } else {
      const error = await response.json();
      console.log('Erro da API:', error); // Adicione esta linha para ver o erro
      showMessage(`Erro: ${error.msg || error.message || "Ocorreu um erro. Tente novamente."}`);
    }
  } catch (err) {
    showMessage('Erro ao se conectar com a API.'); // Exibe uma mensagem de erro de conexão
    console.error(err); // Mostra o erro no console
  }
}

// Função para validar o formulário de login
function validateForm(form) {
  const email = form.querySelector('#login-email').value;
  const password = form.querySelector('#login-password').value;

  // Verifica se o email e a senha estão preenchidos
  if (!email || !password) {
    showMessage('Preencha todos os campos.');
    return false;
  }

  return { email, password }; // Retorna os dados do formulário
}

// Função para validar o formulário de registro
function validateRegisterForm(form) {
  const name = form.querySelector('#register-name').value;
  const email = form.querySelector('#register-email').value;
  const password = form.querySelector('#register-password').value;
  const confirmPassword = form.querySelector('#register-confirm-password').value;

  // Verifica se todos os campos estão preenchidos
  if (!name || !email || !password || !confirmPassword) {
    showMessage('Preencha todos os campos.');
    return false;
  }

  // Verifica se as senhas coincidem
  if (password !== confirmPassword) {
    showMessage('As senhas não conferem.');
    return false;
  }

  console.log({ name, email, password, confirmPassword }); // Adiciona log para verificar os valores

  return { name, email, password, confirmPassword }; // Retorna os dados do formulário
}

// Adiciona o evento de envio de formulário para login e registro
document.querySelectorAll('form').forEach(form => {
  form.addEventListener('submit', (e) => {
    e.preventDefault(); // Impede o envio padrão do formulário

    const isRegister = form.querySelector('h4').textContent.toLowerCase() === 'register';
    let formData;

    if (isRegister) {
      formData = validateRegisterForm(form); // Valida o formulário de registro
    } else {
      formData = validateForm(form); // Valida o formulário de login
    }

    // Se os dados forem válidos, envia o formulário
    if (formData) {
      const endpoint = isRegister ? 'register' : 'login';
      sendForm(endpoint, formData); // Envia para o endpoint correto
    }
  });
});

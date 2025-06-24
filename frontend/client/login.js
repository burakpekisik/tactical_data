// Login page functionality
class LoginManager {
  constructor() {
    this.form = document.getElementById("login-form")
    this.usernameInput = document.getElementById("username")
    this.passwordInput = document.getElementById("password")
    this.passwordToggle = document.getElementById("password-toggle")
    this.loginBtn = document.getElementById("login-btn")
    this.errorMessage = document.getElementById("error-message")
    this.errorText = document.getElementById("error-text")
    this.rememberCheckbox = document.getElementById("remember-me")

    this.initializeEventListeners()
    this.checkRememberedUser()
  }

  initializeEventListeners() {
    // Form submission
    this.form.addEventListener("submit", (e) => this.handleLogin(e))

    // Password toggle
    this.passwordToggle.addEventListener("click", () => this.togglePassword())

    // Input validation on blur
    this.usernameInput.addEventListener("blur", () => this.validateUsername())
    this.passwordInput.addEventListener("blur", () => this.validatePassword())

    // Clear error on input
    this.usernameInput.addEventListener("input", () => this.clearError())
    this.passwordInput.addEventListener("input", () => this.clearError())

    // Enter key handling
    this.usernameInput.addEventListener("keypress", (e) => {
      if (e.key === "Enter") {
        this.passwordInput.focus()
      }
    })

    this.passwordInput.addEventListener("keypress", (e) => {
      if (e.key === "Enter") {
        this.form.dispatchEvent(new Event("submit"))
      }
    })
  }

  async handleLogin(e) {
    e.preventDefault()

    const username = this.usernameInput.value.trim()
    const password = this.passwordInput.value

    // Validate inputs
    if (!this.validateForm(username, password)) {
      return
    }

    // Show loading state
    this.setLoadingState(true)

    try {
      // Simulate authentication delay
      await this.authenticateUser(username, password)

      // Handle remember me
      if (this.rememberCheckbox.checked) {
        this.rememberUser(username)
      } else {
        this.forgetUser()
      }

      // Success - redirect to main application
      this.handleLoginSuccess()
    } catch (error) {
      this.handleLoginError(error.message)
    } finally {
      this.setLoadingState(false)
    }
  }

  async authenticateUser(username, password) {
    // Simulate API call delay
    await new Promise((resolve) => setTimeout(resolve, 1500))

    // Demo credentials - in real app, this would be an API call
    const validCredentials = [
      { username: "admin", password: "admin123" },
      { username: "operator", password: "op123" },
      { username: "tactical", password: "tac456" },
      { username: "demo", password: "demo" },
    ]

    const isValid = validCredentials.some((cred) => cred.username === username && cred.password === password)

    if (!isValid) {
      throw new Error("Geçersiz kullanıcı adı veya şifre!")
    }

    // Store user session
    sessionStorage.setItem("isAuthenticated", "true")
    sessionStorage.setItem("username", username)
    sessionStorage.setItem("loginTime", new Date().toISOString())
  }

  validateForm(username, password) {
    let isValid = true

    // Reset validation states
    this.usernameInput.classList.remove("is-invalid")
    this.passwordInput.classList.remove("is-invalid")

    // Validate username
    if (!username) {
      this.usernameInput.classList.add("is-invalid")
      isValid = false
    }

    // Validate password
    if (!password) {
      this.passwordInput.classList.add("is-invalid")
      isValid = false
    }

    return isValid
  }

  validateUsername() {
    const username = this.usernameInput.value.trim()
    if (!username) {
      this.usernameInput.classList.add("is-invalid")
      return false
    }
    this.usernameInput.classList.remove("is-invalid")
    return true
  }

  validatePassword() {
    const password = this.passwordInput.value
    if (!password) {
      this.passwordInput.classList.add("is-invalid")
      return false
    }
    this.passwordInput.classList.remove("is-invalid")
    return true
  }

  togglePassword() {
    const type = this.passwordInput.type === "password" ? "text" : "password"
    this.passwordInput.type = type

    const icon = this.passwordToggle.querySelector("i")
    icon.className = type === "password" ? "bi bi-eye-fill" : "bi bi-eye-slash-fill"
  }

  setLoadingState(loading) {
    const btnText = this.loginBtn.querySelector(".btn-text")
    const btnSpinner = this.loginBtn.querySelector(".btn-spinner")

    if (loading) {
      this.loginBtn.disabled = true
      this.loginBtn.classList.add("loading")
      btnText.textContent = "Giriş yapılıyor..."
      btnSpinner.classList.remove("d-none")
    } else {
      this.loginBtn.disabled = false
      this.loginBtn.classList.remove("loading")
      btnText.textContent = "Giriş Yap"
      btnSpinner.classList.add("d-none")
    }
  }

  handleLoginSuccess() {
    // Show success message briefly
    this.showSuccessMessage()

    // Redirect after short delay
    setTimeout(() => {
      window.location.href = "index.html"
    }, 1000)
  }

  handleLoginError(message) {
    this.errorText.textContent = message
    this.errorMessage.classList.remove("d-none")

    // Add shake animation
    this.form.style.animation = "shake 0.5s ease-in-out"
    setTimeout(() => {
      this.form.style.animation = ""
    }, 500)

    // Focus on username field
    this.usernameInput.focus()
  }

  clearError() {
    this.errorMessage.classList.add("d-none")
    this.usernameInput.classList.remove("is-invalid")
    this.passwordInput.classList.remove("is-invalid")
  }

  showSuccessMessage() {
    const successAlert = document.createElement("div")
    successAlert.className = "alert alert-success"
    successAlert.innerHTML = `
            <i class="bi bi-check-circle-fill me-2"></i>
            Giriş başarılı! Yönlendiriliyorsunuz...
        `

    this.form.insertBefore(successAlert, this.form.firstChild)

    setTimeout(() => {
      successAlert.remove()
    }, 3000)
  }

  rememberUser(username) {
    localStorage.setItem("rememberedUsername", username)
  }

  forgetUser() {
    localStorage.removeItem("rememberedUsername")
  }

  checkRememberedUser() {
    const rememberedUsername = localStorage.getItem("rememberedUsername")
    if (rememberedUsername) {
      this.usernameInput.value = rememberedUsername
      this.rememberCheckbox.checked = true
      this.passwordInput.focus()
    } else {
      this.usernameInput.focus()
    }
  }
}

// Add shake animation CSS
const shakeCSS = `
@keyframes shake {
    0%, 100% { transform: translateX(0); }
    10%, 30%, 50%, 70%, 90% { transform: translateX(-5px); }
    20%, 40%, 60%, 80% { transform: translateX(5px); }
}
`

// Inject shake animation
const style = document.createElement("style")
style.textContent = shakeCSS
document.head.appendChild(style)

// Initialize login manager when DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
  new LoginManager()
})

// Check if user is already authenticated
if (sessionStorage.getItem("isAuthenticated") === "true") {
  window.location.href = "index.html"
}

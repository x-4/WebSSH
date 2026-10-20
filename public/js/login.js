'use strict';

function initLogin() {
  const form = document.getElementById('login-form');
  const usernameEl = document.getElementById('username');
  const passwordEl = document.getElementById('password');
  const errorEl = document.getElementById('error');
  const submitBtn = document.getElementById('submit-btn');

  function setError(message) {
    errorEl.textContent = message || '';
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    setError('');

    const username = usernameEl.value.trim();
    const password = passwordEl.value;
    if (!username || !password) {
      setError('请输入用户名和密码');
      return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = '登录中…';

    try {
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json().catch(() => ({}));

      if (res.ok && data.ok) {
        location.replace('/');
        return;
      }

      if (res.status === 429) {
        setError(data.message || '尝试过于频繁，请稍后再试');
      } else {
        setError(data.message || '登录失败，请检查账号密码');
        passwordEl.select();
      }
    } catch {
      setError('无法连接服务端，请检查网络后重试');
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = '登 录';
    }
  });
}

initLogin();

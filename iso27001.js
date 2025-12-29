// All diese Aufrufe werden AUSGEFÜHRT:

// 1. Öffentliche APIs
fetch('https://api.openai.com/v1/chat/completions', {
  method: 'POST',
  headers: { 'Authorization': 'Bearer YOUR_KEY' },
  body: JSON.stringify({ model: 'gpt-4', messages: [] })
})

// 2. Lokale APIs
fetch('http://localhost:3000/api/data')

// 3. Externe Ressourcen
fetch('https://api.github.com/user/repos')

// 4. Datei-Uploads
fetch('https://upload.example.com', {
  method: 'POST',
  body: formData
})

// 5. Streams
fetch('https://stream.example.com/data')
  .then(response => response.body.getReader())

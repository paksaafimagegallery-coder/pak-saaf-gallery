const CACHE_NAME = 'pak-saaf-cache-v1';
const urlsToCache = ['/', '/index.html', '/login.html', '/manifest.json'];

self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(urlsToCache)));
});

self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request).then(response => {
      return response || fetch(event.request).then(response => {
        return caches.open(CACHE_NAME).then(cache => {
          if(event.request.method === 'GET') cache.put(event.request, response.clone());
          return response;
        });
      });
    }).catch(() => caches.match('/index.html'))
  );
});
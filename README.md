Проект реализует безопасную передачу конфиденциальных токенов через незащищённый канал. Используется:

- Шифрование AES-256 (режим CBC)
- HMAC-SHA256 для проверки целостности и подлинности данных

Таким образом, токен:
- не может быть прочитан без ключа (конфиденциальность),
- не может быть изменён без обнаружения (целостность),

POST /api/token/encrypt
Шифрует и подписывает токен
Пример запроса:
curl -X POST http://localhost:8081/api/token/encrypt \
  -H "Content-Type: application/json" \
  -d '"MY_SECRET_TOKEN_123"'
Пример ответа:
{
  "ciphertext": "kpCSPB/KPBl+txmjYHbKKlI0oSutwMGVI+I24wGcIhI=",
  "hmac": "aR8HStsfR1Eo3IdjyPCuwkG3CQ1C3Xn2sjteNthrzBc=",
  "iv": "UwsaYyeWFNSIIeYPEFNtaw=="
}

POST /api/token/decrypt
Проверяет подпись и расшифровывает токен
Пример запроса:
curl -X POST http://localhost:8081/api/token/decrypt \
  -H "Content-Type: application/json" \
  -d '{"ciphertext":"kpCSPB/KPBl+txmjYHbKKlI0oSutwMGVI+I24wGcIhI=","hmac":"aR8HStsfR1Eo3IdjyPCuwkG3CQ1C3Xn2sjteNthrzBc=","iv":"UwsaYyeWFNSIIeYPEFNtaw=="}'
Пример ответа:
Токен расшифрован: "MY_SECRET_TOKEN_123"

В application.properties добавлены ключи.

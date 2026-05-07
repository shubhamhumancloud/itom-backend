import 'dotenv/config';
import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { ValidationPipe, Logger, RequestMethod } from '@nestjs/common';
import { WsAdapter } from '@nestjs/platform-ws';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  // Use the native `ws` adapter (not socket.io) — agents are non-browser
  // clients, we don't want socket.io's framing overhead or transport
  // negotiation.
  app.useWebSocketAdapter(new WsAdapter(app));
  app.setGlobalPrefix('v1', {
    exclude: [
      { path: 'api/v1/onboarding/(.*)', method: RequestMethod.ALL },
    ],
  });
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
      forbidNonWhitelisted: false,
    }),
  );
  app.enableCors({
    origin: true, // reflect request origin (works with credentials)
    credentials: true,
    allowedHeaders: [
      'Authorization',
      'Content-Type',
      'X-Request-Id',
      'x-internal-api-key',
    ],
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
  });

  const port = parseInt(process.env.PORT || '3005', 10);
  await app.listen(port, '0.0.0.0');
  Logger.log(`ITOM server listening on 0.0.0.0:${port}`, 'Bootstrap');
}
bootstrap();

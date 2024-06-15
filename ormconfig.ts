import { TypeOrmModuleOptions } from '@nestjs/typeorm';
import { User } from './auth/auth.entity';

const config: TypeOrmModuleOptions = {
  type: 'postgres',
  host: process.env.DATABASE_HOST,
  port: parseInt(process.env.DATABASE_PORT, 10),
  username: process.env.DATABASE_USER,
  password: process.env.DATABASE_PASSWORD,
  database: process.env.DATABASE_NAME,
  entities: [User],
  synchronize: true, // 개발 환경에서만 true 설정, 프로덕션 환경에서는 false 설정
};

export = config;
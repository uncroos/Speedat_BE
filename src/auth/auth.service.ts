import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './auth.entity';
import { RegisterDto, LoginDto } from './dto';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import { randomBytes } from 'crypto';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async register(registerDto: RegisterDto): Promise<User> {
    const { email, name, grade, number, password } = registerDto;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await this.userRepository.save({
      email,
      name,
      grade,
      number,
      password: hashedPassword,
    });
    return user;
  }

  async login(loginDto: LoginDto): Promise<{ accessToken: string }> {
    const { email, password } = loginDto;
    const user = await this.userRepository.findOne({ email });
    if (!user) {
      throw new UnauthorizedException('잘못된 이메일 또는 비밀번호입니다.');
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      throw new UnauthorizedException('잘못된 이메일 또는 비밀번호입니다.');
    }
    const payload = { email: user.email, sub: user.id };
    const accessToken = this.jwtService.sign(payload);
    return { accessToken };
  }

  async generateTempPassword(email: string): Promise<void> {
    const user = await this.userRepository.findOne({ email });
    if (!user) {
      throw new UnauthorizedException('잘못된 이메일입니다.');
    }
    const tempPassword = randomBytes(3).toString('hex'); // 6자리 랜덤 숫자 생성
    await this.userRepository.update(user.id, { password: tempPassword });

    const transporter = nodemailer.createTransport({
      host: this.configService.get('SMTP_HOST'),
      port: parseInt(this.configService.get('SMTP_PORT'), 10),
      secure: false,
      auth: {
        user: this.configService.get('SMTP_USER'),
        pass: this.configService.get('SMTP_PASSWORD'),
      },
    });

    const mailOptions = {
      from: this.configService.get('SMTP_USER'),
      to: email,
      subject: '임시 비밀번호 발급',
      text: `임시 비밀번호: ${tempPassword}`,
    };

    await transporter.sendMail(mailOptions);
  }

  async updateInfo(id: number, updateDto: RegisterDto): Promise<User> {
    const { email, name, grade, number, password } = updateDto;
    const hashedPassword = await bcrypt.hash(password, 10);
    return this.userRepository.update(id, {
      email,
      name,
      grade,
      number,
      password: hashedPassword,
    });
  }
}
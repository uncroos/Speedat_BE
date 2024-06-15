import { Controller, Post, Body, Get, UseGuards, Patch, Param } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto, LoginDto } from './dto';
import { JwtAuthGuard } from './jwt-auth.guard';
import { ApiTags, ApiBody, ApiOperation } from '@nestjs/swagger';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @ApiOperation({ summary: '회원 가입' })
  @ApiBody({ type: RegisterDto })
  @Post('register')
  async register(@Body() registerDto: RegisterDto): Promise<User> {
    return this.authService.register(registerDto);
  }

  @ApiOperation({ summary: '로그인' })
  @ApiBody({ type: LoginDto })
  @Post('login')
  async login(@Body() loginDto: LoginDto): Promise<{ accessToken: string }> {
    return this.authService.login(loginDto);
  }

  @ApiOperation({ summary: '임시 비밀번호 발급' })
  @Post('temp-password/:email')
  async generateTempPassword(@Param('email') email: string): Promise<void> {
    return this.authService.generateTempPassword(email);
  }

  @ApiOperation({ summary: '정보 수정' })
  @ApiBody({ type: RegisterDto })
  @UseGuards(JwtAuthGuard)
  @Patch(':id')
  async updateInfo(@Param('id') id: number, @Body() updateDto: RegisterDto): Promise<User> {
    return this.authService.updateInfo(id, updateDto);
  }
}
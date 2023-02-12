import { BadRequestException, Body, Controller, Get, Post, Res, Req } from '@nestjs/common';
import { AppService } from './app.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { Response, Request } from 'express';
import { UnauthorizedException } from '@nestjs/common/exceptions';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService, private jwtService: JwtService) { }

  @Post('register')
  async register(@Body('name') name: string, @Body('email') email: string, @Body('password') password: string) {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await this.appService.create({ name, email, password: hashedPassword });

    delete user.password;
      
      return user;
  }

  @Post('login')
  async login(@Body('email') email: string, @Body('password') password: string,@Res({passthrough: true}) res: Response) {
    const user = await this.appService.findOne({ email });

    if (!user) {
      throw new BadRequestException('Invalid credentials');
    }

    const isPasswordMatching = await bcrypt.compare(password, user.password);

    if (!isPasswordMatching) {
      throw new BadRequestException('Invalid Password');
    }

    const jwt = await this.jwtService.signAsync({ id: user.id });
     res.cookie('jwt', jwt, { httpOnly: true });
    return {message: 'success'};
  }

  @Get('user')
  async user(@Req() request: Request){
    try{
      const cookie = request.cookies['jwt'];

      const data = await this.jwtService.verifyAsync(cookie);
      if(!data){
        throw new UnauthorizedException();
      }

      const user = await this.appService.findOne({id: data['id']});
      const {password, ...result} = user;
      
      return result;
    } catch(e){
      throw new UnauthorizedException();
    }
   
  }

  @Post('logout')
  async logout(@Res({passthrough: true}) res: Response){
    res.clearCookie('jwt');
    return {message: 'success'};
  }
}

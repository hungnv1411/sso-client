import AuthController from '@controllers/auth.controller';
import { Routes } from '@interfaces/routes.interface';
import { Router } from 'express';

class AuthRoute implements Routes {
  public path = '/saml';
  public router = Router();
  public authController = new AuthController();

  constructor() {
    this.initializeRoutes();
  }

  private initializeRoutes() {
    this.router.get(`${this.path}/metadata`, this.authController.metadata);
    this.router.get(`${this.path}/login`, this.authController.logIn);
    this.router.get(`${this.path}/logout`, this.authController.logOut);
    this.router.post(`${this.path}/assert`, this.authController.doAssert);
    this.router.post(`${this.path}/logout`, this.authController.doLogout);
    this.router.get(`/home`, this.authController.home);
  }
}

export default AuthRoute;

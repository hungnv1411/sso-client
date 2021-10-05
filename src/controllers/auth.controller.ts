import AuthService from '@services/auth.service';
import { NextFunction, Request, Response } from 'express';
import fs from 'fs';
import path from 'path';
import { IdentityProvider, IdentityProviderOptions, ServiceProvider, ServiceProviderOptions } from 'saml2-js';

const ssoServerUrl = 'http://localhost:7000';
const spBaseEndpoint = 'http://localhost:3000/saml';

class AuthController {
  public authService = new AuthService();
  private sp: ServiceProvider;
  private idp: IdentityProvider;

  constructor() {
    try {
      const spOptions: ServiceProviderOptions = {
        entity_id: `${spBaseEndpoint}/metadata`,
        private_key: fs.readFileSync(path.join(__dirname, '../../keys/sp-private-key.pem')).toString(),
        certificate: fs.readFileSync(path.join(__dirname, '../../keys/sp-public-cert.pem')).toString(),
        assert_endpoint: `${spBaseEndpoint}/assert`,
      };
      const idpOptions: IdentityProviderOptions = {
        sso_login_url: `${ssoServerUrl}/saml/sso`,
        sso_logout_url: `${ssoServerUrl}/saml/slo`,
        certificates: [fs.readFileSync(path.join(__dirname, '../../keys/idp-public-cert.pem')).toString()],
        // allow_unencrypted_assertion: true,
      };
      this.sp = new ServiceProvider(spOptions);
      this.idp = new IdentityProvider(idpOptions);
    } catch (err) {
      console.log('init service provider failed', err);
    }
  }

  public metadata = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      res.type('application/xml');
      res.send(this.sp.create_metadata());
    } catch (error) {
      next(error);
    }
  };

  public logIn = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      this.sp.create_login_request_url(
        this.idp,
        {
          relay_state: '/home',
          force_authn: true,
        },
        function (err, login_url, request_id) {
          if (err != null) return res.send(500);
          res.redirect(login_url);
        },
      );
    } catch (error) {
      next(error);
    }
  };

  public logOut = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      if (req.session.user) {
        var options = {
          name_id: req.session.user.name_id,
          session_index: req.session.user.session_index,
        };

        this.sp.create_logout_request_url(this.idp, options, function (err, logout_url) {
          if (err != null) return res.send(500);
          res.redirect(logout_url);
        });
      } else {
        res.redirect('/');
      }
    } catch (error) {
      next(error);
    }
  };

  public doAssert = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const options = { request_body: req.body };
    this.sp.post_assert(this.idp, options, function (err, saml_response) {
      console.log('assert error', err);
      if (err != null) return res.send(500);

      console.log('saml response', saml_response);
      req.session.user = saml_response.user;
      if (req.body.RelayState) {
        res.redirect(req.body.RelayState);
      } else {
        res.send(`Hello ${saml_response.user.name_id}!`);
      }
    });
  };

  public doLogout = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    res.send('logged out');
  };

  public home = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    res.render('home', {
      title: 'Home',
      userName: req.session.user ? req.session.user.name_id : 'null',
    });
  };

  public redirectLoginMiddleware = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    if (!req.session.user) {
      if (req.query['origin'] != 'sso') {
        this.sp.create_login_request_url(
          this.idp,
          {
            relay_state: `${spBaseEndpoint}${req.path}`,
            force_authn: false,
          },
          (err, login_url, request_id) => {
            if (err != null) return res.send(500);
            res.redirect(login_url);
          },
        );
      } else {
        next();
      }
    } else {
      next();
    }
  };
}

export default AuthController;

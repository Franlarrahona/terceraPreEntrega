import { Router } from "express";
import passport from "passport";

import config from "../config.js";
import { createHash, isValidPassword, verifyRequiredBody } from "../services/utils.js";
import UsersController from "../controllers/user.controller.js";
import initAuthStrategies from "../auth/passport.strategies.js";

const router = Router();
const controller = new UsersController();
initAuthStrategies()

router.post('/login',verifyRequiredBody(['email','password']), async (req,res) => {
    try{
        const {email, password} = req.body;
        const foundUser = await controller.getOne({ email: email});

        if(foundUser && isValidPassword(password, foundUser.password)) {

            const { password, ...filteredFoundUser} = foundUser;
            req.session.user = filteredFoundUser;
            req.session.save(err =>{
                if(err) return res.status(500).send({origin: config.SERVER, payload: null, error: err.message});
                
                res.redirect('/products/1');
            });
        }else{
            res.status(401).send({ origin: config.SERVER, payload: 'Datos de acceso no válidos' });
        }

    }catch(err){
        res.status(500).send({ origin: config.SERVER, payload: null, error: err.message });
    }
}); 
router.post('/register', async(req,res) =>{
    try{
        const {firstName, lastName, email, password} = req.body;
        const foundUser = await controller.getOne({email:email});
        console.log(foundUser)

        if(!foundUser){
            const process = await controller.add({firstName, lastName, email, password: createHash(password)});
            res.status(200).send({origin: config.SERVER, payload: process});
        }else{
            res.status(400).send({ origin: config.SERVER, payload:'el email ya se encuentra registrado'})
        }
    }catch (err){
        res.status(500).send({origin: config.SERVER, payload: null, error: err.message});
    }
});
router.get('/logout', async(req,res) =>{
    try{
        req.session.destroy((err) =>{
            if(err) return res.status(500).send({origin: config.SERVER, payload:'error al ejecutar logout', error:err})
            res.redirect('/login')
        });
    }catch(err){
        res.status(500).send({ origin: config.SERVER, payload: null, error: err.message})
    }
})

router.post('/pplogin', verifyRequiredBody(['email','password']), passport.authenticate('pplogin', {failureRedirect: `/login?error=${encodeURI('Usuario o clave no válidos')}`}), async ( req, res) =>{
    try{

        req.session.user = req.user;
        req.session.save( err =>{
            if(err) return res.status(500).send({ origin: config.SERVER, payload: null, error:err.message});
            res.redirect('/products');

        });
    }catch(err){
        res.status(500).send({ origin: config.SERVER, payload: null, error: err.message});
    }
});

export default router;
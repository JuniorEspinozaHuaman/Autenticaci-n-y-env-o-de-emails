const catchError = require('../utils/catchError');
const User = require('../models/User');
const bcrypt = require('bcrypt');
const sendEmail = require('../utils/sendEmail');
const EmailCode = require('../models/EmailCode');
const jwt = require('jsonwebtoken');

const getAll = catchError(async (req, res) => {
    const results = await User.findAll();
    return res.json(results);
});

const create = catchError(async (req, res) => {
    const { email, password, firstName, lastName, country, image, frontBaseUrl } = req.body;
    const encriptedPassword = await bcrypt.hash(password, 10);
    const result = await User.create({
        email, password: encriptedPassword, firstName, lastName, country, image
    });
    const code = require('crypto').randomBytes(32).toString('hex');
    const link = `${frontBaseUrl}/${code}`;

    await EmailCode.create({
        code,
        userId: result.id
    });

    await sendEmail({
        to: email,
        subject: "Verificate email for user app",
        html: `
        <html>
        <head>
        </head>
        <body style="display: flex; justify-content: center;">
            <section style="width: 600px; height: 250px; background-color: rgba(236, 240, 228, 0.479); text-align: center; border-radius: 8px;">
                <h1 style="margin-bottom: 50px;">Hello ${firstName} ${lastName}</h1>
                <p><a href="${link}" style="text-decoration: none; color: white; background-color: rgb(89, 138, 230); padding: 10px; border-radius: 8px;">Verification Code</a></p>
                <p><b>Thanks for sign up in user app</b></p>
            </section>
        </body>
    </html>
        `
    });
    return res.status(201).json(result);
});

const getOne = catchError(async (req, res) => {
    const { id } = req.params;
    const result = await User.findByPk(id);
    if (!result) return res.sendStatus(404);
    return res.json(result);
});

const remove = catchError(async (req, res) => {
    const { id } = req.params;
    await User.destroy({ where: { id } });
    return res.sendStatus(204);
});

const update = catchError(async (req, res) => {
    const { id } = req.params;
    const { firstName, lastName, country, image } = req.body;
    const result = await User.update(
        { firstName, lastName, country, image},
        { where: { id }, returning: true }
    );
    if (result[0] === 0) return res.sendStatus(404);
    return res.json(result[1][0]);
});

const verifyEmail = catchError(async(req, res) => {
    const { code } = req.params;
    const emailCode = await EmailCode.findOne({ where: { code }});
    if(!emailCode) return res.staus(401).json({ message: "Código inválido"});
    
    await User.update(
        { isVerified: true },
        { where: {id: emailCode.userId}, returning: true }
        );
    await emailCode.destroy();

     return res.json({ message: "Código verificado"});
});

const login = catchError(async(req, res) => {
    const { email, password} = req.body;
    const user = await User.findOne({ where: { email}});
    if(!user) return res.status(401).json({ message: "Correo invalido"});
    const isValid = await bcrypt.compare( password, user.password);
    if(!isValid) return res.status(401).json({ message: "Contraseña incorrecta"});
    if(user.isVerified === false) return res.status(401).json({ message: "Usuario sin verificar"});

    const token = jwt.sign(
        {user},
        process.env.TOKEN_SECRET,
        { expiresIn: "1d"}
    );
    return res.json({ user, token });
});

const loggedUser = catchError(async(req, res) => {
    return res.json(req.user);
});

const resetPassword = catchError(async(req, res) => {
    const { email, frontBaseUrl } = req.body;
    const user = await User.findOne({ where: {email: email}});
    if(!user) return res.staus(401).json({ message: "Correo invalido"});

    const code = require('crypto').randomBytes(32).toString('hex');
    const link = `${frontBaseUrl}/${code}`

    await EmailCode.create({
        code,
        userId: user.id
    });

    await sendEmail({
        to: email,
        subject: "Account recovery",
        html: `
        <html>
        <head>
        </head>
        <body style="display: flex; justify-content: center;">
            <section style="width: 600px; height: 250px; background-color: rgba(236, 240, 228, 0.479); text-align: center; border-radius: 8px;">
                <h1 style="margin-bottom: 50px;">Hello!</h1>
                <p>Hello, a password reset has been requested for your <span style="color: blue; cursor: pointer;" ><u>${email}</u></span> account, click the button below to change your password</p>
                <p><a href="${link}" style="text-decoration: none; color: white; background-color: rgb(89, 138, 230); padding: 10px; border-radius: 8px;">Account recovery</a></p>
                <p><b>If you didn't make the password reset request, just ignore this message.</b></p>
            </section>
        </body>
    </html>
        `
    });
    return res.json(user);
});

const updatePassword = catchError(async(req, res) => {
    const { password } = req.body;
    const { code } = req.params;
    const emailCode = await EmailCode.findOne({ where: { code: code }});
    if(!emailCode) return res.status(401).json({ message: "Código inválido" });
    const encriptedPassword = await bcrypt.hash( password, 10 );
    await User.update(
        {password: encriptedPassword},
        { where: { id: emailCode.userId}, returning: true}
        );

    await emailCode.destroy();
    
    return res.json({ message: "La contraseña se actualizo con exito"});
})
module.exports = {
    getAll,
    create,
    getOne,
    remove,
    update,
    verifyEmail,
    login,
    loggedUser,
    resetPassword,
    updatePassword
}
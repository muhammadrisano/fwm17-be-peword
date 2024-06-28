const createError = require("http-errors");
const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");
const workers = require("../../models/workers");
const users = require("../../models/users");
const fetch = require("node-fetch");
const cloudinary = require("../../utils/cloudinary");

const { response } = require("../../helpers/common");
const { registerSchema, updateSchema } = require("./request_model");
const register = async (req, res, next) => {
  try {
    const { error, value } = registerSchema(req.body);
    if (error) {
      return next(new createError.BadRequest(error.details[0].message));
    }
    const { email, password, name, phone } = value;
    const { rowCount } = await users.findByEmail(email, {
      relation: "workers",
    });
    if (rowCount) {
      return next(createError(403, "user sudah terdaftar"));
    }
    const salt = bcrypt.genSaltSync(10);
    const passwrodHash = bcrypt.hashSync(password, salt);

    const user = {
      id: uuidv4(),
      email,
      password: passwrodHash,
      role: "worker",
    };
    const worker = {
      id: uuidv4(),
      name,
      user_id: user.id,
      phone,
    };
    await users.create(user);
    await workers.register(worker);

    const notifData = {
      app_id: process.env.ONESIGNAL_ID,
      name: "info register user",
      included_segments: ["Total Subscriptions"],
      contents: {
        en: `${worker.name} telah bergabung`,
      },
      data:{
        worker
      }
    };
    const resNotif = await fetch("https://api.onesignal.com/notifications", {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        Authorization : `Bearer ${process.env.ONESIGNAL_API_KEY}`
      },
      body: JSON.stringify(notifData)
    })
    const result = await resNotif.json()
    console.log(result);
    response(res, null, 201, "user berhasil resgiter");
  } catch (error) {
    console.log(error);
    next(new createError.InternalServerError());
  }
};

const update = async (req, res, next) => {
  try {
    const { error, value } = updateSchema(req.body);
    if (error) {
      return next(new createError.BadRequest(error.details[0].message));
    }
    const email = req.decoded.email;
    const {
      rows: [user],
    } = await users.findByEmail(email);

    await workers.update(value, user.user_id);
    response(res, value, 200, "update profile workers success ");
  } catch (error) {
    console.log(error);
    next(new createError.InternalServerError());
  }
};

const profile = async (req, res, next) => {
  try {
    const email = req.decoded.email;
    const {
      rows: [user],
    } = await users.findByEmail(email, { relation: "workers" });
    if (!user) {
      return next(new createError[403]());
    }
    delete user.password;
    response(res, user, 200, "get workers success");
  } catch (error) {
    console.log(error);
    next(new createError.InternalServerError());
  }
};

const detail = async (req, res, next) => {
  try {
    const id = req.params.id;
    console.log(id);
    const {
      rows: [worker],
    } = await workers.findOne({ id });
    if (!worker) {
      throw new Error("Worker not found");
    }
    response(res, worker, 200, "get workers success");
  } catch (error) {
    console.log(error);
    next(error);
  }
};

const selectAll = async (req, res, next) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 5;
  const sort = req.query.sort || "created_at";
  const sortBy = req.query.sortBy || "DESC";
  const search = req.query.search || "";
  const offset = (page - 1) * limit;
  let result = [];
  const { rows } = await workers.findAll({
    limit,
    offset,
    search,
    sort,
    sortBy,
  });
  for (obj of rows) {
    const { rows: res } = await workers.SelectSkillWorker({ id: obj.id });
    const skills = res.map(([item]) => {
      return item;
    });
    result = [
      ...result,
      {
        ...obj,
        skills: skills,
      },
    ];
  }
  const {
    rows: [count],
  } = await workers.countWorkers({ search });
  const totalData = parseInt(count.total);
  const totalPage = Math.ceil(totalData / limit);
  const pagination = {
    currentPage: page,
    limit,
    totalData,
    totalPage,
  };
  // setTimeout(()=>{
  response(res, result, 200, "success get data workers", pagination);
  // }, 5000)
};

const updateFoto = async (req, res, next) => {
  try {
    const email = req.decoded.email;
    const {
      rows: [user],
    } = await users.findByEmail(email);

    const result = await cloudinary.uploader.upload(req.file.path);
    const urlPhoto = result.secure_url;
    await workers.updatePhoto(urlPhoto, user.user_id);
    response(
      res,
      { photo: urlPhoto },
      200,
      "update photo profile workers success "
    );
  } catch (error) {
    console.log(error);
    next(error);
  }
};
const deleteWorker = async(req, res, next)=>{
  try {
    const id = req.params.id
    const {rows} = await users.deleteOne(id)
    response(res, rows, 200, "delete workers success ");


  } catch (error) {
    console.log(error);
    next(error);
  }
}
module.exports = {
  register,
  update,
  selectAll,
  profile,
  detail,
  updateFoto,
  deleteWorker
};

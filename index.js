import mongoose from 'mongoose';
import WebSocket, { WebSocketServer } from 'ws';
import dotenv from 'dotenv'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'
import express from 'express'
dotenv.config(); 

const saltRounds = 10; 
const { Schema } = mongoose;
const uri = "mongodb+srv://<id>:<password>@democluster.ru2irax.mongodb.net/?appName=democluster";

let activesession = {
  classId: null,
  startedAt: null,
  attendance: {}
};

await mongoose.connect(uri);
console.log("MongoDB connected");

const userSchema = new Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: {
    type: String,
    enum: ['teacher', 'student'],
    required: true
  }
});

const User = mongoose.model('User', userSchema);

const classSchema = new Schema({
  classname: { type: String, required: true },
  teacherID: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  studentIds: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }
  ]
});

const Class = mongoose.model('Class', classSchema);

const attendanceSchema = new Schema({
  classId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Class',
    required: true
  },
  studentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  status: {
    type: String,
    enum: ['present', 'absent', 'late'],
    required: true
  }
});

attendanceSchema.index(
  { classId: 1, studentId: 1 },
  { unique: true }
);

const Attendance = mongoose.model('Attendance', attendanceSchema);

async function checkEmail(emailID){
  const email = await User.findOne({ email: emailID });
  if(email){
    return {
      success: false,
      error: "Email already exists"
    }
  }
  return {success: true}
}

async function hashPassword(pw) {
  return bcrypt.hash(pw, saltRounds);
}


function generateaccesstoken(data){
  return jwt.sign(data , process.env.ACCESS_TOKEN_SECRET , {expiresIn : '1d'});
}

const verifyJWT = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({success: false, error: "Unauthorized, token missing or invalid" });
  try {
    req.user = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    next();
  }catch {
    return res.status(401).json({success: false, error: "Unauthorized, token missing or invalid" });
  }
};

const app = express()
app.use(express.json())
const server = app.listen(3000, () =>
  console.log("Server running on 3000")
);
let refreshTokens = [];
const wss = new WebSocketServer({server});

function broadcast(data) {
  const message = JSON.stringify(data);
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  });
};

wss.on('connection', async (ws, request) => {
  try {
    const url = new URL(request.url, 'http://localhost');
    const token = url.searchParams.get('token');
    if(!token){
      ws.send(JSON.stringify({
        event: "ERROR",
        data: {
          message: "Unauthorized or invalid token"
        }
      }));
      ws.close(1008, 'Token required');
      return;
    }
    const decoded = jwt.verify(
      token,
      process.env.ACCESS_TOKEN_SECRET
    );
    ws.user = decoded;
    console.log('Client authenticated:', ws.user);

    ws.on('message', async (msg) => {
      try{
        const data = JSON.parse(message.toString()); 
          if(data.event === "ATTENDANCE_MARKED"){
            if(ws.user.role !== "teacher"){
              ws.send(JSON.stringify({
                event: "ERROR",
                data: {
                  message: "Forbidden, teacher event only"
                }
              }));
              return;
            }
            if(!activesession.classId){
              ws.send(JSON.stringify({
                event: "ERROR",
                data: {
                  message: "No active session"
                }
              }));
              return;
            }
            activesession.attendance[data.data.studentId] = data.data.status;
            broadcast({
              event: "ATTENDANCE_MARKED",
              data: {
                studentId: data.data.studentId,
                status: data.data.status
              }
            });
          }        
          if (data.event === "TODAY_SUMMARY") {
            if(ws.user.role !== "teacher"){
              ws.send(JSON.stringify({
                event: "ERROR",
                data: {
                  message: "Forbidden, teacher event only"
                }
              }));
              return;
            }
            const values = Object.values(activesession.attendance || {});
            const presentCount = values.filter(v => v === "present").length;
            const absentCount = values.filter(v => v === "absent").length;
            broadcast({
              event: "TODAY_SUMMARY",
              data: {
                present: presentCount,
                absent: absentCount,
                total: values.length
              }
            });
          }
          if(data.event === "DONE"){
            if(ws.user.role !== "teacher"){
              ws.send(JSON.stringify({
                event: "ERROR",
                data: {
                  message: "Forbidden, teacher event only"
                }
              }));
              return;
            }
            if(!activesession.classId){
              ws.send(JSON.stringify({
                event: "ERROR",
                data: {
                  message: "No active session"
                }
              }));
              return;
            }
            const classData = await Class.findOne({ _id: activesession.classId });
            for(const studentId of classData.studentIds){
              if(!activesession.attendance[studentId.toString()]){
                activesession.attendance[studentId.toString()] = "absent";
              }
            }
            const attendancePromises = [];
            for(const [studentId, status] of Object.entries(activesession.attendance)){
              attendancePromises.push(
                Attendance.findOneAndUpdate(
                  { classId: activesession.classId, studentId: studentId },
                  { status: status },
                  { upsert: true, new: true }
                )
              );
            }
            await Promise.all(attendancePromises);
            const values = Object.values(activesession.attendance);
            const presentCount = values.filter(v => v === "present").length;
            const absentCount = values.filter(v => v === "absent").length;
            broadcast({
              event: "DONE",
              data: {
                message: "Attendance persisted",
                present: presentCount,
                absent: absentCount,
                total: values.length
              }
            });
          }
          if(data.event === "MY_ATTENDANCE"){
            if(ws.user.role !== "student"){
                ws.send(JSON.stringify({
                  event: "ERROR",
                  data: {
                    message: "Forbidden, student event only"
                  }
                }));
                return;
              }
              const userStatus = activesession.attendance?.[ws.user.userId] ?? "not yet updated";
              ws.send(JSON.stringify({
                event : data.event,
                data : {
                  status : userStatus
                }
              }));
          }
      }catch (err) {
        console.error('WebSocket message error:', err);
          ws.send(JSON.stringify({
            event: "ERROR",
            data: {
              message: "Invalid message format"
            }
          }));
        }
      })
  }catch (err) {
    console.error('WebSocket auth failed:', err.message);
    ws.send(JSON.stringify({
      event: "ERROR",
      data: {
        message: "Unauthorized or invalid token"
      }
    }));
    ws.close(1008, 'Invalid token');
  }
});

app.use(async (req, res, next) => {
  if (req.path === '/auth/signup') {
    const data = req.body;
    if (!data || !data.password) {
      return res.status(400).json({
        success: false,
        error: "Password is required"
      });
    }
    if (data.password.length < 6) {
      return res.status(400).json({
        success: false,
        error: "Password should have min 6 characters"
      });
    }
    const isExists = await checkEmail(data.email);
    if(!isExists.success){
      return res.status(400).json(isExists);
    }
  }
  if(req.path == '/auth/me') {
    const token = req.headers['authorization']?.split(" ")[1];
    if(!token){
      return res.status(401).json({
        success: false,
        error: "Unauthorized, token missing or invalid"
      })
    }
    try{
      const decoded = jwt.verify(token , process.env.ACCESS_TOKEN_SECRET);
      req.user = decoded;
    }catch{
      return res.status(401).json({
        success: false,
        error: "Unauthorized, token missing or invalid"
      })
    }
  }
  next();
});

app.get('/', (req, res) => {
  res.send('Hello World!')
})

app.get('/auth/me' , async (req , res) => {
  const userId = req.user.userId;
  const data = await User.findOne({ _id: userId });
  res.status(200).json({ 
    success: true,
    data : {
      _id: data._id,
      name: data.name,
      email: data.email,
      role: data.role
    }
  });
})

app.post('/token' , (req, res) => {
  const refreshtoken = req.body.token;
  if(refreshtoken == null) return res.sendStatus(401);
  if(!refreshTokens.includes(refreshtoken)) return res.sendStatus(401);
  jwt.verify(refreshtoken , process.env.REFRESH_TOKEN_SECRET , (err , user) => {
    if(err) return res.sendStatus(403);
    const accesstoken = generateaccesstoken(user);
    res.json({
      access_token : accesstoken
    });
  })
})

app.post('/auth/signup' , async (req, res) => {
  const data = req.body;
  const user = await User.create({
    name : data.name,
    email : data.email,
    password : await hashPassword(data.password),
    role : data.role
  }) 
  await user.save();
  return res.status(201).json({
    success: true,
    data: {
      _id: user._id,
      name: user.name,
      email: user.email,
      role: user.role
    }
  })
})

app.post('/auth/login' , async (req, res) => {
  const data = req.body;
  const email = await User.findOne({ email: data.email});
  if(email){
    const payload = {
      userId : email._id ,
      role : email.role
    }
    const access_token = generateaccesstoken(payload);
    const refresh_token = jwt.sign(payload , process.env.REFRESH_TOKEN_SECRET);
    refreshTokens.push(refresh_token);
    res.status(200).json({
      success : true,
      data : {
        token : access_token,
      }
    })
  }else{
    res.status(400).json({
      success : false,
      error: "Invalid email or password"
    })
  }
})

app.post('/class' , verifyJWT , async (req , res) => {
  if(req.user.role != "teacher"){
    return res.status(403).json({
      success: false,
      error: "Forbidden, teacher access required"
    })
  }
  const class_modal = await Class.create({
    classname : req.body.className , 
    teacherID : req.user.userId ,
    studentIds : [],
  })
  await class_modal.save();
  return res.status(201).json({
    success: true,
    data: {
      _id: class_modal._id,
      className: class_modal.classname,
      teacherId: class_modal.teacherID,
      studentIds: class_modal.studentIds
    }
  })
})

app.post('/class/:id/add-student' , verifyJWT , async (req , res)=>{
  if(req.user.role != "teacher"){
    return res.status(403).json({
      success: false,
      error: "Forbidden, teacher access required"
    })
  }
  const data = await Class.findOne({teacherID : req.user.userId , _id : req.params.id});
  if(!data){
    return res.status(404).json({
      success: false,
      error: "Class not found or you don't own this class"
    });
  }
  data.studentIds.push(req.body.studentId);
  const updatedData = await data.save();
  return res.status(200).json({
    success: true,
    data: {
      _id: updatedData._id,
      className: updatedData.classname,
      teacherId: updatedData.teacherID,
      studentIds: updatedData.studentIds
    }
  });
})

app.get('/class/:id' , verifyJWT , async (req, res) => {
  if(req.user.role === "teacher"){
    const classdata = await Class.findOne({_id : req.params.id, teacherID: req.user.userId}).populate('studentIds', 'name email');
    if(!classdata){
      return res.status(404).json({
        success: false,
        error: "Class not found or you don't own this class"
      });
    }
    return res.status(200).json({
      success: true,
      data: {
        _id: classdata._id,
        className: classdata.classname,
        teacherId: classdata.teacherID,
        students: classdata.studentIds 
      }
    });
  }
  if(req.user.role === "student"){
    const classdata = await Class.findOne({_id : req.params.id, studentIds: req.user.userId}).populate('studentIds', 'name email'); 
    if(!classdata){
      return res.status(404).json({
        success: false,
        error: "Class not found or you are not enrolled"
      });
    }
    return res.status(200).json({
      success: true,
      data: {
        _id: classdata._id,
        className: classdata.classname,
        teacherId: classdata.teacherID,
        students: classdata.studentIds
      }
    });
  }
  return res.status(404).json({
    success: false,
    error: "Forbidden, not class teacher"
  });
})

app.get('/students' , verifyJWT , async (req , res) =>{
  if(req.user.role != "teacher"){
    return res.status(403).json({
      success: false,
      error: "Forbidden, teacher access required"
    })
  }
  const students = await User.find({role: 'student'} , {password : 0});
  return res.status(200).json({
      success: true,
      data: {...students}
  });
})

app.get('/class/:id/my-attendance' , verifyJWT , async (req , res) => {
  if(req.user.role != "student"){
    return res.status(403).json({
      success: false,
      error: "Forbidden, student access required"
    })
  }
  const classdata = await Class.findOne({_id : req.params.id ,studentIds : req.user.userId});
  if(!classdata){
    return res.status(404).json({
      success: false,
      error: "Class not found or you are not enrolled"
    });
  }
  const studentAttendance = await Attendance.findOne({studentId : req.user.userId, classId: req.params.id});
  return res.status(200).json({
    success : true,
    data : {
      classId : req.params.id,
      status : studentAttendance ? studentAttendance.status : null
    }
  });
})

app.post('/attendance/start' , verifyJWT , async (req , res) => {
  if(req.user.role != "teachet"){
    return res.status(403).json({
      success: false,
      error: "Forbidden, student access required"
    })
  }
  const classdata = await Class.findOne({_id : req.body.classId, teacherID: req.user.userId});
  if(!classdata){
    return res.status(404).json({
      success: false,
      error: "Class not found or you don't own this class"
    });
  }
  activesession = {
    classId: req.body.classId,
    startedAt: new Date().toISOString(),
    attendance: {}
  };
  return res.status(200).json({
    success : true,
    data : {
      classId : req.body.classId,
      startedAt : activesession.startedAt
    }
  });
})
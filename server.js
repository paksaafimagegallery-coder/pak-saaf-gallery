require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const multer = require('multer');
const path = require('path');
const helmet = require('helmet');
const archiver = require('archiver');
const axios = require('axios');
const PDFDocument = require('pdfkit');

const app = express();

// --- Security Middleware ---
app.use(helmet({
  contentSecurityPolicy: false,
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('MongoDB Error:', err));

// --- Models ---
const Village = mongoose.model('Village', new mongoose.Schema({
  District: String, 
  Tehsil: String, 
  'Village Councils': String
}));

const User = mongoose.model('User', new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: String,
  role: { type: String, default: 'officer' },
  vcId: { type: mongoose.Schema.Types.ObjectId, ref: 'Village', default: null, unique: true, sparse: true },
  district: String, tehsil: String, vcName: String,
  mustChangePassword: { type: Boolean, default: false }
}));

const DateEntry = mongoose.model('DateEntry', new mongoose.Schema({
  vcId: { type: mongoose.Schema.Types.ObjectId, ref: 'Village' },
  date: String,
  pairs: [{
    slot: Number,
    before: { url: String, cloudinaryId: String },
    after: { url: String, cloudinaryId: String }
  }]
}));

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: { folder: 'pak-saaf-gallery', allowed_formats: ['jpg', 'png', 'jpeg', 'webp'] }
});
const upload = multer({ 
  storage: storage, 
  limits: { fileSize: 500 * 1024 } 
});

function auth(req, res, next) {
  const token = req.header('Authorization') || req.query.token;
  if (!token) return res.status(401).json({ msg: 'No token' });
  try {
    req.user = jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET);
    next();
  } catch (e) { res.status(403).json({ msg: 'Invalid or expired token' }); }
}

// --- Pakistan Standard Time (PKT) Date Helpers ---
function getPakistanDateString(date = new Date()) {
  const pkTime = new Date(date.getTime() + (5 * 60 * 60 * 1000));
  const year = pkTime.getUTCFullYear();
  const month = String(pkTime.getUTCMonth() + 1).padStart(2, '0');
  const day = String(pkTime.getUTCDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}
function getRecentPakistanDates(count) {
  const dates = [];
  let daysAgo = 0;
  while(dates.length < count) {
    const d = new Date();
    d.setDate(d.getDate() - daysAgo);
    const pkDate = new Date(d.getTime() + (5 * 60 * 60 * 1000));
    if (pkDate.getUTCDay() !== 0) { 
      dates.push(getPakistanDateString(d));
    }
    daysAgo++;
  }
  return dates;
}

// --- AUTO-DELETE LOGIC (6 Days Rolling Window per VC) ---
async function cleanupOldDates() {
  try {
    const vcIds = await DateEntry.distinct('vcId');
    for (const vcId of vcIds) {
      const entries = await DateEntry.find({ vcId }).sort({ date: -1 });
      const entriesToDelete = entries.slice(6); 
      for (const entry of entriesToDelete) {
        for (const pair of entry.pairs) {
          await cloudinary.uploader.destroy(pair.before.cloudinaryId);
          await cloudinary.uploader.destroy(pair.after.cloudinaryId);
        }
        await DateEntry.findByIdAndDelete(entry._id);
      }
    }
  } catch (err) { console.error('Cleanup error:', err); }
}
cleanupOldDates();
setInterval(cleanupOldDates, 60 * 60 * 1000);

// --- Routes ---
app.get('/api/hierarchy', async (req, res) => { try { res.json(await Village.find()); } catch(e) { res.json([]); } });

// --- DISTRICT THUMBNAILS API ---
app.get('/api/district-thumbnails', async (req, res) => {
  try {
    const pipeline = [
      { $sort: { date: -1 } },
      { $lookup: { from: "villages", localField: "vcId", foreignField: "_id", as: "village" } },
      { $unwind: "$village" },
      { $group: { _id: "$village.District", latestEntry: { $first: "$$ROOT" } } }
    ];
    const results = await DateEntry.aggregate(pipeline);
    const thumbnails = {};
    results.forEach(r => {
      const pairs = r.latestEntry.pairs;
      if (pairs && pairs.length > 0) {
        thumbnails[r._id] = pairs.slice(0, 4).map(p => p.before.url.replace('/upload/', '/upload/w_200,h_125,c_fill/'));
      }
    });
    res.json(thumbnails);
  } catch (e) { res.json({}); }
});

app.get('/api/images', async (req, res) => {
  try {
    const { vcId, date } = req.query;
    let filter = {};
    if (vcId) filter.vcId = vcId;
    if (date) filter.date = date;
    res.json(await DateEntry.find(filter).sort({ date: -1 }));
  } catch (e) { res.json([]); }
});

app.post('/api/login', async (req, res) => {
  const user = await User.findOne({ username: req.body.username });
  if (!user || !(await bcrypt.compare(req.body.password, user.password))) return res.status(401).json({ msg: 'Invalid credentials' });
  const token = jwt.sign({ id: user._id, role: user.role, vcId: user.vcId, mustChangePassword: user.mustChangePassword }, process.env.JWT_SECRET, { expiresIn: '8h' });
  res.json({ token, role: user.role, vcId: user.vcId, mustChangePassword: user.mustChangePassword, district: user.district, tehsil: user.tehsil, vcName: user.vcName });
});

app.post('/api/change-password', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    user.password = await bcrypt.hash(req.body.newPassword, 10);
    user.mustChangePassword = false;
    await user.save();
    res.json({ msg: 'Password changed successfully' });
  } catch(e) { res.status(500).json({ msg: 'Failed to change password' }); }
});

app.post('/api/register', async (req, res) => {
  try {
    const userCount = await User.countDocuments();
    const isFirstUser = userCount === 0;
    if (!isFirstUser) {
      const token = req.header('Authorization');
      if (!token) return res.status(403).json({ msg: 'Admin access only' });
      const verifiedUser = jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET);
      if (verifiedUser.role !== 'admin') return res.status(403).json({ msg: 'Admin access only' });
    }
    const { username, password, vcId, district, tehsil, vcName } = req.body;
    const existingUser = await User.findOne({ username: username.toLowerCase() });
    if (existingUser) return res.status(400).json({ msg: 'Username already exists.' });
    if (vcId) {
      const existingVcUser = await User.findOne({ vcId });
      if (existingVcUser) return res.status(400).json({ msg: 'This Village Council already has an account.' });
    }
    const hash = await bcrypt.hash(password || '12345', 10);
    await User.create({ username: username.toLowerCase(), password: hash, role: isFirstUser ? 'admin' : 'officer', vcId: vcId || null, district: district || 'All', tehsil: tehsil || '', vcName: vcName || '', mustChangePassword: !isFirstUser });
    res.json({ msg: 'Account created successfully' });
  } catch (e) { res.status(400).json({ msg: e.code === 11000 ? 'Duplicate detected.' : 'Error creating user' }); }
});

app.get('/api/users/paginated', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ msg: 'Admin only' });
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 50; 
    const search = req.query.search || '';
    const dateFilter = req.query.date || '';
    
    let query = { role: 'officer' };
    if (search) {
      query = { role: 'officer', $or: [{ username: { $regex: search, $options: 'i' } }, { vcName: { $regex: search, $options: 'i' } }] };
    }
    
    const totalUsers = await User.countDocuments(query);
    const users = await User.find(query).select('-password').skip((page - 1) * limit).limit(limit).lean();
    
    if (dateFilter && users.length > 0) {
      const vcIds = users.map(u => u.vcId).filter(id => id);
      const entries = await DateEntry.find({ vcId: { $in: vcIds }, date: dateFilter });
      const entryMap = {};
      entries.forEach(e => entryMap[e.vcId.toString()] = e.pairs.length);
      users.forEach(u => { u.uploadedPairs = u.vcId ? (entryMap[u.vcId.toString()] || 0) : 0; });
    }
    res.json({ users, totalPages: Math.ceil(totalUsers / limit), currentPage: page, totalUsers });
  } catch(e) { res.status(500).json({ msg: 'Failed' }); }
});

app.post('/api/users/generate', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ msg: 'Admin only' });
  try {
    const villages = await Village.find().sort({ District: 1, Tehsil: 1, 'Village Councils': 1 });
    const existingUsers = await User.find({ role: 'officer' });
    const existingUsernames = new Set(existingUsers.map(u => u.username));
    const existingVcIds = new Set(existingUsers.map(u => u.vcId?.toString()));
    const districtCounters = {};
    const newUsers = [];
    const hashedPassword = await bcrypt.hash('12345', 10);
    
    for (const v of villages) {
      if (existingVcIds.has(v._id.toString())) continue;
      let distCode = v.District.substring(0, 3).toLowerCase().replace(/[^a-z]/g, '');
      if (!districtCounters[distCode]) districtCounters[distCode] = 0;
      let username;
      do {
        districtCounters[distCode]++;
        username = `${distCode}_${String(districtCounters[distCode]).padStart(3, '0')}`;
      } while (existingUsernames.has(username)); 
      existingUsernames.add(username);
      newUsers.push({ username, password: hashedPassword, role: 'officer', vcId: v._id, district: v.District, tehsil: v.Tehsil, vcName: v['Village Councils'], mustChangePassword: true });
    }
    if (newUsers.length > 0) await User.insertMany(newUsers);
    res.json({ msg: `Generated ${newUsers.length} new accounts. Existing VCs skipped.` });
  } catch (err) { res.status(500).json({ msg: 'Generation failed' }); }
});

app.post('/api/users/reset/:id', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ msg: 'Admin only' });
  try {
    const user = await User.findById(req.params.id);
    user.password = await bcrypt.hash('12345', 10);
    user.mustChangePassword = true;
    await user.save();
    res.json({ msg: 'Password reset to 12345' });
  } catch(e) { res.status(500).json({ msg: 'Failed' }); }
});

app.delete('/api/users/:id', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ msg: 'Admin only' });
  try { await User.findByIdAndDelete(req.params.id); res.json({ msg: 'User deleted' }); } catch(e) { res.status(500).json({ msg: 'Failed' }); }
});

app.get('/api/users/csv', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ msg: 'Admin only' });
  try {
    const users = await User.find();
    let csv = 'Username,Temp Password,District,Tehsil,Village Council,Role,Password Changed\n';
    users.forEach(u => { csv += `${u.username},${u.mustChangePassword ? '12345' : 'Changed'},${u.district || 'All'},${u.tehsil || ''},${u.vcName || ''},${u.role},${u.mustChangePassword ? 'No' : 'Yes'}\n`; });
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=vc_accounts.csv');
    res.send(csv);
  } catch(e) { res.status(500).json({ msg: 'Failed' }); }
});

// --- ANALYTICS ROUTE (Date-wise Split) ---
app.get('/api/stats/compliance', auth, async (req, res) => {
  try {
    const today = getPakistanDateString();
    const recentDates = getRecentPakistanDates(6);
    
    let totalVcs, uploadedTodayCount, uploaded6DaysCount;
    let chartLabels = [];
    let chartData = [];

    if (req.user.role === 'admin') {
      totalVcs = await Village.countDocuments();
      uploadedTodayCount = await DateEntry.countDocuments({ date: today, 'pairs.3': { $exists: true } });
      uploaded6DaysCount = (await DateEntry.find({ date: { $in: recentDates }, 'pairs.3': { $exists: true } }).distinct('vcId')).length;
      
      for (const d of recentDates) {
        const formattedDate = new Date(d+'T00:00:00').toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' });
        chartLabels.push(formattedDate);
        const compliantCount = await DateEntry.countDocuments({ date: d, 'pairs.3': { $exists: true } });
        chartData.push(totalVcs > 0 ? Math.round((compliantCount / totalVcs) * 100) : 0);
      }
    } else {
      totalVcs = 1;
      const vcId = req.user.vcId;
      uploadedTodayCount = await DateEntry.countDocuments({ vcId, date: today, 'pairs.3': { $exists: true } }) > 0 ? 1 : 0;
      uploaded6DaysCount = await DateEntry.countDocuments({ vcId, date: { $in: recentDates }, 'pairs.3': { $exists: true } }) > 0 ? 1 : 0;
      
      for (const d of recentDates) {
        const formattedDate = new Date(d+'T00:00:00').toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' });
        chartLabels.push(formattedDate);
        const entry = await DateEntry.findOne({ vcId, date: d });
        const pairs = entry ? entry.pairs.length : 0;
        chartData.push(Math.round((pairs / 4) * 100));
      }
    }
    res.json({ totalVcs, uploadedTodayCount, uploaded6DaysCount, chartLabels, chartData });
  } catch(e) { res.status(500).json({ msg: 'Stats failed' }); }
});

// --- ZERO COMPLIANCE ROUTE ---
app.get('/api/stats/noncompliant', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ msg: 'Admin only' });
  try {
    const selectedDate = req.query.date;
    let query = { 'pairs.3': { $exists: true } }; 
    if (selectedDate === 'overall') {
      query.date = { $in: getRecentPakistanDates(6) };
    } else {
      query.date = selectedDate || getPakistanDateString();
    }
    const compliantVcIds = await DateEntry.find(query).distinct('vcId');
    const nonCompliantVillages = await Village.find({ _id: { $nin: compliantVcIds } }).sort({ District: 1, Tehsil: 1, 'Village Councils': 1 });
    const officers = await User.find({ vcId: { $in: nonCompliantVillages.map(v => v._id) } });
    const officerMap = {};
    officers.forEach(o => officerMap[o.vcId] = o.username);
    const result = nonCompliantVillages.map(v => ({ district: v.District, tehsil: v.Tehsil, vcName: v['Village Councils'], officer: officerMap[v._id] || 'No Account' }));
    res.json({ count: result.length, villages: result, date: selectedDate });
  } catch(e) { res.status(500).json({ msg: 'Failed' }); }
});

// --- UPLOAD LOGIC ---
app.post('/api/upload', auth, (req, res, next) => {
  upload.fields([
    { name: 'pair1_before', maxCount: 1 }, { name: 'pair1_after', maxCount: 1 },
    { name: 'pair2_before', maxCount: 1 }, { name: 'pair2_after', maxCount: 1 },
    { name: 'pair3_before', maxCount: 1 }, { name: 'pair3_after', maxCount: 1 },
    { name: 'pair4_before', maxCount: 1 }, { name: 'pair4_after', maxCount: 1 }
  ])(req, res, (err) => {
    if (err instanceof multer.MulterError) return res.status(400).json({ msg: `Upload Error: ${err.message}` });
    else if (err) return res.status(500).json({ msg: 'Server Error during upload.' });
    next();
  });
}, async (req, res) => {
  try {
    const vcId = req.user.role === 'admin' ? req.body.vcId : req.user.vcId;
    const { date } = req.body;
    const recentValidDates = getRecentPakistanDates(6);
    if (!recentValidDates.includes(date)) {
      if (req.files) Object.values(req.files).flat().forEach(f => cloudinary.uploader.destroy(f.filename));
      return res.status(400).json({ msg: 'Invalid date. You can only upload for the current or last 5 working days (Sundays skipped).' });
    }
    let entry = await DateEntry.findOne({ vcId, date });
    let isNew = false;
    if (!entry) {
      const dateCount = await DateEntry.countDocuments({ vcId });
      if (dateCount >= 6) {
        Object.values(req.files).flat().forEach(f => cloudinary.uploader.destroy(f.filename));
        return res.status(400).json({ msg: 'Your 6 days are complete. Wait for next day.' });
      }
      entry = new DateEntry({ vcId, date, pairs: [] }); isNew = true;
    }
    let uploadedCount = 0; let rejectedMsg = '';
    for (let i = 1; i <= 4; i++) {
      const beforeFile = req.files[`pair${i}_before`]?.[0];
      const afterFile = req.files[`pair${i}_after`]?.[0];
      if (beforeFile && afterFile) {
        if (entry.pairs.some(p => p.slot === i)) {
          cloudinary.uploader.destroy(beforeFile.filename); cloudinary.uploader.destroy(afterFile.filename);
          rejectedMsg += `Pair ${i} already exists. Admin must delete first. `;
        } else {
          entry.pairs.push({ slot: i, before: { url: beforeFile.path, cloudinaryId: beforeFile.filename }, after: { url: afterFile.path, cloudinaryId: afterFile.filename } });
          uploadedCount++;
        }
      } else if (beforeFile || afterFile) {
        if (beforeFile) cloudinary.uploader.destroy(beforeFile.filename);
        if (afterFile) cloudinary.uploader.destroy(afterFile.filename);
        rejectedMsg += `Pair ${i} needs BOTH Before and After. `;
      }
    }
    if (uploadedCount === 0 && !isNew) return res.json({ msg: rejectedMsg || 'No new pairs uploaded.' });
    try { await entry.save(); } catch (dbErr) {
      console.error("DB Save Failed! Deleting orphaned Cloudinary files.");
      for (let i = 1; i <= 4; i++) {
        const bFile = req.files[`pair${i}_before`]?.[0]; const aFile = req.files[`pair${i}_after`]?.[0];
        if (bFile) cloudinary.uploader.destroy(bFile.filename); if (aFile) cloudinary.uploader.destroy(aFile.filename);
      }
      return res.status(500).json({ msg: 'Database error. Images rejected.' });
    }
    res.json({ msg: `Uploaded ${uploadedCount} pair(s) successfully. ${rejectedMsg}` });
  } catch (err) { res.status(500).json({ msg: 'Upload failed' }); }
});

app.delete('/api/dateentry/:entryId', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ msg: 'Admin only.' });
  try {
    const entry = await DateEntry.findById(req.params.entryId);
    if (!entry) return res.status(404).json({ msg: 'Not found' });
    for (const pair of entry.pairs) { await cloudinary.uploader.destroy(pair.before.cloudinaryId); await cloudinary.uploader.destroy(pair.after.cloudinaryId); }
    await DateEntry.findByIdAndDelete(entry._id);
    res.json({ msg: 'Date deleted successfully' });
  } catch (err) { res.status(500).json({ msg: 'Failed' }); }
});

// --- PDF & ZIP ARCHIVE ROUTES ---
async function generatePdf(doc, entries, villages) {
  const pageWidth = doc.page.width - 100; const imgWidth = (pageWidth - 20) / 2; const imgHeight = imgWidth * 0.75;
  const villageMap = {}; villages.forEach(v => villageMap[v._id] = v);
  for (const entry of entries) {
    const village = villageMap[entry.vcId]; if (!village) continue;
    for (const pair of entry.pairs) {
      if (doc.y > doc.page.height - 250) doc.addPage();
      let currentY = doc.y;
      doc.fontSize(12).fillColor('#074822').text(`${village.District} > ${village.Tehsil} > ${village['Village Councils']} | Date: ${entry.date} | Pair ${pair.slot}`, 50, currentY);
      currentY += 20;
      const bUrl = pair.before.url.replace('/upload/', '/upload/w_500,h_375,c_fill/'); const aUrl = pair.after.url.replace('/upload/', '/upload/w_500,h_375,c_fill/');
      try {
        const bRes = await axios.get(bUrl, { responseType: 'arraybuffer' }); doc.image(Buffer.from(bRes.data, 'binary'), 50, currentY, { width: imgWidth, height: imgHeight });
        const aRes = await axios.get(aUrl, { responseType: 'arraybuffer' }); doc.image(Buffer.from(aRes.data, 'binary'), 50 + imgWidth + 20, currentY, { width: imgWidth, height: imgHeight });
        currentY += imgHeight + 5; doc.fontSize(10).fillColor('black').text('Before', 50, currentY, { width: imgWidth, align: 'center' }); doc.text('After', 50 + imgWidth + 20, currentY, { width: imgWidth, align: 'center' });
        doc.y = currentY + 20;
      } catch(e) { console.log("PDF Img Error"); }
    }
  }
}
app.get('/api/download/pdf/tehsil/:district/:tehsil', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ msg: 'Admin only' });
  try {
    const { district, tehsil } = req.params; const villages = await Village.find({ District: district, Tehsil: tehsil }); const vcIds = villages.map(v => v._id);
    const entries = await DateEntry.find({ vcId: { $in: vcIds } }).sort({ date: 1, vcId: 1 });
    if (entries.length === 0) return res.status(404).send('No images found.'); if (entries.length > 50) return res.status(400).send('Too many images for one PDF (Server limit). Please use ZIP Archive.');
    res.setHeader('Content-Type', 'application/pdf'); res.setHeader('Content-Disposition', `attachment; filename=${district}_${tehsil}_Report.pdf`);
    const doc = new PDFDocument({ size: 'A4', margin: 50 }); doc.pipe(res);
    doc.fontSize(20).fillColor('#074822').text(`${district} - ${tehsil}`, { align: 'center' }); doc.moveDown(0.5);
    doc.fontSize(12).fillColor('#8a9b91').text(`Sanitation Report (Generated: ${new Date().toLocaleDateString()})`, { align: 'center' }); doc.moveDown(2);
    await generatePdf(doc, entries, villages); doc.end();
  } catch (err) { res.status(500).send('PDF Generation Failed'); }
});
app.get('/api/download/pdf/district/:district', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ msg: 'Admin only' });
  try {
    const { district } = req.params; const villages = await Village.find({ District: district }); const vcIds = villages.map(v => v._id);
    const entries = await DateEntry.find({ vcId: { $in: vcIds } }).sort({ date: 1, vcId: 1 });
    if (entries.length === 0) return res.status(404).send('No images found.'); if (entries.length > 50) return res.status(400).send('Too many images for one PDF (Server limit). Please use ZIP Archive.');
    res.setHeader('Content-Type', 'application/pdf'); res.setHeader('Content-Disposition', `attachment; filename=${district}_Report.pdf`);
    const doc = new PDFDocument({ size: 'A4', margin: 50 }); doc.pipe(res);
    doc.fontSize(20).fillColor('#074822').text(`${district} District Report`, { align: 'center' }); doc.moveDown(0.5);
    doc.fontSize(12).fillColor('#8a9b91').text(`Sanitation Report (Generated: ${new Date().toLocaleDateString()})`, { align: 'center' }); doc.moveDown(2);
    await generatePdf(doc, entries, villages); doc.end();
  } catch (err) { res.status(500).send('PDF Generation Failed'); }
});
app.get('/api/download/pdf/overall', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ msg: 'Admin only' });
  try {
    const villages = await Village.find(); const entries = await DateEntry.find().sort({ date: 1, vcId: 1 });
    if (entries.length === 0) return res.status(404).send('No images found.'); if (entries.length > 50) return res.status(400).send('Too many images for one PDF (Server limit). Please use ZIP Archive.');
    res.setHeader('Content-Type', 'application/pdf'); res.setHeader('Content-Disposition', `attachment; filename=Overall_Provincial_Report.pdf`);
    const doc = new PDFDocument({ size: 'A4', margin: 50 }); doc.pipe(res);
    doc.fontSize(20).fillColor('#074822').text(`Overall Provincial Report`, { align: 'center' }); doc.moveDown(0.5);
    doc.fontSize(12).fillColor('#8a9b91').text(`Sanitation Report (Generated: ${new Date().toLocaleDateString()})`, { align: 'center' }); doc.moveDown(2);
    await generatePdf(doc, entries, villages); doc.end();
  } catch (err) { res.status(500).send('PDF Generation Failed'); }
});
app.get('/api/download/zip/district/:district', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ msg: 'Admin only' });
  try {
    const district = req.params.district; const villages = await Village.find({ District: district }); const vcIds = villages.map(v => v._id);
    const entries = await DateEntry.find({ vcId: { $in: vcIds } });
    if (entries.length === 0) return res.status(404).send('No images found.');
    res.setHeader('Content-Type', 'application/zip'); res.setHeader('Content-Disposition', `attachment; filename=${district}_6Day_Archive.zip`);
    const zip = archiver('zip', { zlib: { level: 9 } }); zip.pipe(res);
    const villageMap = {}; villages.forEach(v => villageMap[v._id] = v);
    for (const entry of entries) {
      const village = villageMap[entry.vcId];
      for (const pair of entry.pairs) {
        const bRes = await axios.get(pair.before.url, { responseType: 'arraybuffer' }); zip.append(Buffer.from(bRes.data, 'binary'), { name: `${village.Tehsil}/${village['Village Councils']}/${entry.date}/pair${pair.slot}_before.jpg` });
        const aRes = await axios.get(pair.after.url, { responseType: 'arraybuffer' }); zip.append(Buffer.from(aRes.data, 'binary'), { name: `${village.Tehsil}/${village['Village Councils']}/${entry.date}/pair${pair.slot}_after.jpg` });
      }
    }
    await zip.finalize();
  } catch (err) { res.status(500).send('Failed'); }
});
app.get('/api/download/zip/overall', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ msg: 'Admin only' });
  try {
    const villages = await Village.find(); const entries = await DateEntry.find();
    if (entries.length === 0) return res.status(404).send('No images found.');
    res.setHeader('Content-Type', 'application/zip'); res.setHeader('Content-Disposition', `attachment; filename=Overall_Provincial_Archive.zip`);
    const zip = archiver('zip', { zlib: { level: 9 } }); zip.pipe(res);
    const villageMap = {}; villages.forEach(v => villageMap[v._id] = v);
    for (const entry of entries) {
      const village = villageMap[entry.vcId]; if (!village) continue;
      for (const pair of entry.pairs) {
        const bRes = await axios.get(pair.before.url, { responseType: 'arraybuffer' }); zip.append(Buffer.from(bRes.data, 'binary'), { name: `${village.District}/${village.Tehsil}/${village['Village Councils']}/${entry.date}/pair${pair.slot}_before.jpg` });
        const aRes = await axios.get(pair.after.url, { responseType: 'arraybuffer' }); zip.append(Buffer.from(aRes.data, 'binary'), { name: `${village.District}/${village.Tehsil}/${village['Village Councils']}/${entry.date}/pair${pair.slot}_after.jpg` });
      }
    }
    await zip.finalize();
  } catch (err) { res.status(500).send('Failed'); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
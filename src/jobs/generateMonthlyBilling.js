
import dotenv from "dotenv";
import {
  initializeApp,
  cert,
} from "firebase-admin/app";
import {
  getFirestore,
  FieldValue,
} from "firebase-admin/firestore";

dotenv.config();

const projectId = process.env.FIREBASE_PROJECT_ID;
const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
const privateKey = process.env.FIREBASE_PRIVATE_KEY;

if (!projectId || !clientEmail || !privateKey) {
  throw new Error("Firebase credentials are missing.");
}

const app = initializeApp({
  credential: cert({
    projectId,
    clientEmail,
    privateKey: privateKey
      .replace(/\\n/g, "\n")
      .replace(/^["']|["']$/g, "")
      .trim(),
  }),
});

const firestore = getFirestore(app);

function getMyanmarMonth() {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Yangon",
    year: "numeric",
    month: "2-digit",
  }).formatToParts(new Date());

  const year = parts.find((p) => p.type === "year").value;
  const month = parts.find((p) => p.type === "month").value;

  return `${year}-${month}`;
}

function getBillingMonths(startMonth, endMonth) {
  const months = [];

  let [year, month] = startMonth.split("-").map(Number);

  while (true) {
    const value = `${year}-${String(month).padStart(2, "0")}`;

    if (value > endMonth) break;

    months.push(value);

    month++;

    if (month > 12) {
      month = 1;
      year++;
    }

    if (months.length > 499) {
      throw new Error("Billing period exceeds the allowed limit.");
    }
  }

  return months;
}

async function generateMonthlyBilling() {
  const currentMonth = getMyanmarMonth();

  console.log(`Starting monthly billing: ${currentMonth}`);

  const profilesSnapshot = await firestore
    .collection("paymentProfiles")
    .where("status", "==", "Active")
    .get();

  const bulkWriter = firestore.bulkWriter();

  let createdCount = 0;
  let skippedCount = 0;
  let failedCount = 0;

  const writeTasks = [];

  for (const profileDoc of profilesSnapshot.docs) {
    const profile = profileDoc.data();

    const studentId = profileDoc.id;
    const monthlyFee = profile.monthlyFee;
    const category = profile.paymentCategory;
    const startMonth = profile.billingStartMonth;

    if (
      !category ||
      !Number.isFinite(monthlyFee) ||
      monthlyFee <= 0 ||
      !startMonth ||
      !/^\d{4}-(0[1-9]|1[0-2])$/.test(startMonth)
    ) {
      skippedCount++;
      continue;
    }

    const lastChargeMonth = profile.lastChargeMonth || null;

    if (
      lastChargeMonth &&
      !/^\d{4}-(0[1-9]|1[0-2])$/.test(lastChargeMonth)
    ) {
      skippedCount++;
      continue;
    }

    const endMonth =
      lastChargeMonth && lastChargeMonth < currentMonth
        ? lastChargeMonth
        : currentMonth;

    if (startMonth > endMonth) {
      skippedCount++;
      continue;
    }

    const months = getBillingMonths(startMonth, endMonth);

    for (const billingMonth of months) {
      const recordRef = firestore
        .collection("paymentRecords")
        .doc(`${studentId}_${billingMonth}`);

      const task = bulkWriter
        .create(recordRef, {
          studentId,
          studentName: profile.studentName || "",
          dormitoryNumber: profile.dormitoryNumber || "",
          billingMonth,
          monthlyFee,
          paidAmount: 0,
          balance: monthlyFee,
          status: "Unpaid",
          createdAt: FieldValue.serverTimestamp(),
          updatedAt: FieldValue.serverTimestamp(),
        })
        .then(() => {
          createdCount++;
        })
        .catch((error) => {
          if (
            error.code === 6 ||
            error.code === "already-exists"
          ) {
            skippedCount++;
            return;
          }

          failedCount++;
          console.error(
            `Failed: ${studentId} ${billingMonth}`,
            error.message
          );
        });

      writeTasks.push(task);
    }
  }

  await Promise.all(writeTasks);
  await bulkWriter.close();

  console.log("Monthly billing completed.");
  console.log({
    currentMonth,
    activeProfiles: profilesSnapshot.size,
    createdCount,
    skippedCount,
    failedCount,
  });

  if (failedCount > 0) {
    throw new Error("Some monthly billing records failed.");
  }
}

generateMonthlyBilling()
  .then(async () => {
    await app.delete();
    process.exit(0);
  })
  .catch(async (error) => {
    console.error("Monthly billing job failed:", error);
    await app.delete();
    process.exit(1);
  });

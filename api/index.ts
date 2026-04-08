import serverless from "serverless-http";
import { createServer } from "../server/index";

// Export the Express app as a serverless function handler
const app = createServer();
export default serverless(app);

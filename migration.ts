// 导入所需的库
import fetch from 'node-fetch';
import * as fs from 'fs';
import dotenv from 'dotenv';
import { z } from 'zod';
import path from 'path';

interface Auth0User {
  created_at: string;
  email: string;
  email_verified: boolean;
  identities: Array<{
    connection: string;
    provider: string;
    user_id: string;
    isSocial: boolean;
  }>;
  name: string;
  nickname: string;
  picture: string;
  updated_at: string;
  user_id: string;
  username: string;
  last_ip: string;
  last_login: string;
  logins_count: number;
  blocked_for: any[];
  guardian_authenticators: any[];
  passkeys: any[];
  phone?: string;
}

interface LogtoUser {
  username?: string;
  primaryEmail?: string;
  name?: string;
  avatar?: string;
  password?: string;
  passwordDigest?: string;
  passwordAlgorithm?: 'Argon2i' | 'SHA256' | 'MD5' | 'Bcrypt';
  customData: {
    auth0_user_id?: string;
    email_verified?: boolean;
    nickname?: string;
    last_ip?: string;
    last_login?: string;
    logins_count?: number;
    identities?: any;
    blocked_for?: any[];
    guardian_authenticators?: any[];
    passkeys?: any[];
    auth0_connection?: string;
    auth0_provider?: string;
    auth0_is_social?: boolean;
  };
  profile: Record<string, any>;
}

interface LogtoUserResponse {
  primaryEmail?: string;
  primaryPhone?: string;
  id: string;  // 用户ID
}

interface LogtoUsersResponse {
  users: LogtoUserResponse[];
  total?: number;        // API 可能在响应体中返回总数
  page?: number;         // 当前页码
  pageSize?: number;     // 每页大小
}

// 加载环境变量
const envResult = dotenv.config();
if (envResult.error) {
  console.error('无法加载 .env 文件:', envResult.error);
  process.exit(1);
}

// 定义配置验证 schema
const ConfigSchema = z.object({
  LOGTO_TENANT_ID: z.string().min(1, '租户 ID 不能为空'),
  LOGTO_CLIENT_ID: z.string().min(1, 'Client ID 不能为空'),
  LOGTO_CLIENT_SECRET: z.string().min(1, 'Client Secret 不能为空'),
  AUTH0_USERS_FILE: z.string().min(1, '用户数据文件路径不能为空'),
  MIGRATION_DELAY: z.string().transform(val => parseInt(val, 10)).pipe(
    z.number().min(100, '延迟时间不能小于 100ms')
  ),
  INITIAL_ACCESS_TOKEN: z.string().optional()
});

// 验证并获取配置
function getConfig() {
  try {
    const config = ConfigSchema.parse({
      LOGTO_TENANT_ID: process.env.LOGTO_TENANT_ID,
      LOGTO_CLIENT_ID: process.env.LOGTO_CLIENT_ID,
      LOGTO_CLIENT_SECRET: process.env.LOGTO_CLIENT_SECRET,
      AUTH0_USERS_FILE: process.env.AUTH0_USERS_FILE,
      MIGRATION_DELAY: process.env.MIGRATION_DELAY,
      INITIAL_ACCESS_TOKEN: process.env.INITIAL_ACCESS_TOKEN,
    });

    return config;
  } catch (error) {
    if (error instanceof z.ZodError) {
      console.error('\n配置验证失败:');
      error.errors.forEach(err => {
        console.error(`- ${err.path.join('.')}: ${err.message}`);
      });
    } else {
      console.error('\n配置验证时发生错误:', error);
    }
    process.exit(1);
  }
}

// 获取配置
const CONFIG = getConfig();

// 使用配置
const LOGTO_BASE_URL = `https://${CONFIG.LOGTO_TENANT_ID}.logto.app`;
const LOGTO_API = `${LOGTO_BASE_URL}/api/users`;
let ACCESS_TOKEN = process.env.INITIAL_ACCESS_TOKEN || ''; // 使用环境变量中的初始 token

interface TokenResponse {
  access_token: string;
  // 可以添加其他字段如果需要
  token_type?: string;
  expires_in?: number;
}

// 定义API响应类型
interface ApiResponse {
  users?: LogtoUserResponse[];
  total?: number;
}

// 修改读取用户函数使用配置的文件路径
async function readAuth0Users(): Promise<Auth0User[]> {
  try {
    const data = fs.readFileSync(CONFIG.AUTH0_USERS_FILE, 'utf-8');
    return JSON.parse(data);
  } catch (error) {
    console.error(`读取用户数据文件 ${CONFIG.AUTH0_USERS_FILE} 失败:`, error);
    return [];
  }
}

function convertToLogtoUser(auth0User: Auth0User): LogtoUser {
  const primaryIdentity = auth0User.identities[0];
  
  return {
    primaryEmail: auth0User.email,  // 必需字段：邮箱
    username: auth0User.username || auth0User.nickname,  // 用户名，使用 username 或 nickname
    name: auth0User.name || auth0User.nickname,  // 显示名称
    password: 'Logto@2024',  // 设置一个默认密码，用户可以后续修改
    avatar: auth0User.picture,
    customData: {
      auth0_user_id: auth0User.user_id,
      email_verified: auth0User.email_verified,
      nickname: auth0User.nickname,
      last_ip: auth0User.last_ip,
      last_login: auth0User.last_login,
      logins_count: auth0User.logins_count,
      identities: auth0User.identities,
      blocked_for: auth0User.blocked_for,
      guardian_authenticators: auth0User.guardian_authenticators,
      passkeys: auth0User.passkeys,
      auth0_connection: primaryIdentity?.connection,
      auth0_provider: primaryIdentity?.provider,
      auth0_is_social: primaryIdentity?.isSocial
    },
    profile: {
      nickname: auth0User.nickname,
      preferredUsername: auth0User.username,
      created_at: auth0User.created_at,
      updated_at: auth0User.updated_at
    }
  };
}

// 修改刷新 token 函数使用配置
async function refreshAccessToken(): Promise<string> {
  try {
    // 构建正确的 token endpoint
    const tokenEndpoint = `https://${CONFIG.LOGTO_TENANT_ID}.logto.app/oidc/token`;
    
    // 使用 M2M 应用的凭证
    const tokenRequest = {
      grant_type: 'client_credentials',
      resource: `https://${CONFIG.LOGTO_TENANT_ID}.logto.app/api`,
      scope: 'all'
    };

    // 使用 M2M 应用的 ID 和 Secret 进行 Basic 认证
    const authString = Buffer.from(`${CONFIG.LOGTO_CLIENT_ID}:${CONFIG.LOGTO_CLIENT_SECRET}`).toString('base64');
    
    const response = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${authString}`
      },
      body: new URLSearchParams(tokenRequest)
    });

    if (!response.ok) {
      const responseText = await response.text();
      throw new Error(`获取 token 失败: ${responseText}`);
    }

    const data = await response.json() as TokenResponse;
    console.log('成功获取新 token, 过期时间:', data.expires_in, '秒');
    console.log('新 token:', data.access_token);
    return data.access_token;
  } catch (error) {
    console.error('刷新 token 失败:', error);
    throw error;
  }
}

function isTokenExpired(token: string): boolean {
  try {
    const [, payload] = token.split('.');
    const decodedPayload = JSON.parse(Buffer.from(payload, 'base64').toString());
    const expirationTime = decodedPayload.exp * 1000; // 转换为毫秒
    const currentTime = Date.now();
    
    return currentTime >= expirationTime;
  } catch (error) {
    console.error('Token 解析失败:', error);
    return true;
  }
}

// 添加一个新的函数来统一处理 token
async function ensureValidToken(): Promise<string> {
  if (!ACCESS_TOKEN || isTokenExpired(ACCESS_TOKEN)) {
    console.log('Token 不存在或已过期，正在刷新...');
    ACCESS_TOKEN = await refreshAccessToken();
  } else {
    console.log('使用现有有效 token');
  }
  return ACCESS_TOKEN;
}

async function createLogtoUser(logtoUser: LogtoUser): Promise<any> {
  try {
    const token = await ensureValidToken();

    console.log('正在创建用户:', logtoUser.primaryEmail);
    console.log('请求 URL:', LOGTO_API);
    
    const response = await fetch(LOGTO_API, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(logtoUser)
    });

    const responseText = await response.text();
    console.log('API 响应:', responseText);

    if (!response.ok) {
      let errorDetail;
      try {
        errorDetail = JSON.parse(responseText);
      } catch {
        errorDetail = responseText;
      }
      throw new Error(`创建用户失败: ${response.status} ${JSON.stringify(errorDetail)}`);
    }

    return JSON.parse(responseText);
  } catch (error) {
    if (error instanceof Error && error.message.includes('JWT verification failed')) {
      ACCESS_TOKEN = await refreshAccessToken();
      return createLogtoUser(logtoUser);
    }
    throw error;
  }
}

async function checkUserExists(email?: string, phone?: string): Promise<boolean> {
  try {
    const token = await ensureValidToken();
    
    // 如果既没有邮箱也没有手机号，返回 false
    if (!email && !phone) {
      console.log('用户没有邮箱和手机号，无法验证是否存在');
      return false;
    }

    // 检查邮箱
    if (email) {
      const emailResponse = await fetch(`${LOGTO_API}?page=1&page_size=10&search=${encodeURIComponent(email)}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (!emailResponse.ok) {
        if (emailResponse.status === 401) {
          ACCESS_TOKEN = await refreshAccessToken();
          return checkUserExists(email, phone);
        }
        throw new Error(`查询用户失败: ${emailResponse.status}`);
      }

      const emailData = await emailResponse.json() as ApiResponse | LogtoUserResponse[];
      const emailUsers = Array.isArray(emailData) ? emailData : emailData.users;
      if (emailUsers?.some(user => user.primaryEmail === email)) {
        console.log(`找到匹配的邮箱用户: ${email}`);
        return true;
      }
    }

    // 检查手机号
    if (phone) {
      const phoneResponse = await fetch(`${LOGTO_API}?page=1&page_size=10&search=${encodeURIComponent(phone)}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (!phoneResponse.ok) {
        if (phoneResponse.status === 401) {
          ACCESS_TOKEN = await refreshAccessToken();
          return checkUserExists(email, phone);
        }
        throw new Error(`查询用户失败: ${phoneResponse.status}`);
      }

      const phoneData = await phoneResponse.json() as ApiResponse | LogtoUserResponse[];
      const phoneUsers = Array.isArray(phoneData) ? phoneData : phoneData.users;
      if (phoneUsers?.some(user => user.primaryPhone === phone)) {
        console.log(`找到匹配的手机号用户: ${phone}`);
        return true;
      }
    }

    return false;
  } catch (error) {
    console.error(`检查用户是否存在时出错:`, error);
    return false;
  }
}

async function getAllLogtoUsers(): Promise<LogtoUserResponse[]> {
  try {
    const token = await ensureValidToken();
    const PAGE_SIZE = 100; // Logto API 的最大页大小限制
    let allUsers: LogtoUserResponse[] = [];
    let page = 1;
    
    // 首先获取第一页来获取总数
    const initialResponse = await fetch(`${LOGTO_API}?page=1&page_size=${PAGE_SIZE}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    if (!initialResponse.ok) {
      throw new Error(`获取用户列表失败: ${initialResponse.status}`);
    }

    // 获取响应数据
    const firstPageData = await initialResponse.json() as ApiResponse | LogtoUserResponse[];
    
    // 处理两种可能的响应格式
    const users = Array.isArray(firstPageData) ? firstPageData : firstPageData.users;
    if (!users) {
      console.error('API 响应格式:', firstPageData);
      throw new Error('无法解析用户数据');
    }
    
    allUsers = allUsers.concat(users);
    
    // 获取总用户数
    const totalUsers = Array.isArray(firstPageData) 
      ? parseInt(initialResponse.headers.get('total-number') || '0')
      : (firstPageData.total || parseInt(initialResponse.headers.get('total-number') || '0'));

    console.log('Logto 总用户数:', totalUsers);
    console.log('每页大小:', PAGE_SIZE);

    // 计算需要的页数
    const totalPages = Math.ceil(totalUsers / PAGE_SIZE);
    console.log(`需要查询 ${totalPages} 页数据`);

    // 添加重试机制
    const maxRetries = 3;
    // 获取剩余页的数据
    for (page = 2; page <= totalPages; page++) {
      console.log(`正在获取第 ${page}/${totalPages} 页数据...`);
      let retries = 0;
      while (retries < maxRetries) {
        try {
          const response = await fetch(`${LOGTO_API}?page=${page}&page_size=${PAGE_SIZE}`, {
            method: 'GET',
            headers: {
              'Authorization': `Bearer ${token}`
            }
          });

          if (!response.ok) {
            throw new Error(`获取第 ${page} 页数据失败: ${response.status}`);
          }

          const pageData = await response.json() as ApiResponse | LogtoUserResponse[];
          const pageUsers = Array.isArray(pageData) ? pageData : pageData.users;
          if (!pageUsers) {
            throw new Error('无法解析用户数据');
          }
          allUsers = allUsers.concat(pageUsers);
          break; // 成功后跳出重试循环
        } catch (error) {
          retries++;
          if (retries === maxRetries) {
            throw error;
          }
          console.log(`第 ${retries} 次重试获取第 ${page} 页数据...`);
          await new Promise(resolve => setTimeout(resolve, 1000));
        }
      }
    }

    console.log(`成功获取所有 ${allUsers.length} 个用户数据`);
    return allUsers;
  } catch (error) {
    console.error('获取所有用户失败:', error);
    throw error;
  }
}

async function migrateUsers() {
  try {
    // 确保 logs 目录存在
    const logsDir = path.join(__dirname, 'logs');
    if (!fs.existsSync(logsDir)) {
      fs.mkdirSync(logsDir, { recursive: true });
    }

    // 创建日志文件
    const migrationLogPath = path.join(__dirname, 'logs', 'migration.log');
    const errorLogPath = path.join(__dirname, 'logs', 'migration-errors.log');
    const successLogPath = path.join(__dirname, 'logs', 'success-users.log');
    
    const logStream = fs.createWriteStream(migrationLogPath, { flags: 'a' });
    const successStream = fs.createWriteStream(successLogPath, { flags: 'a' });

    // 添加迁移开始时间戳
    const startTime = new Date().toISOString();
    logStream.write(`\n=== 迁移开始于 ${startTime} ===\n`);

    // 读取 Auth0 用户
    const auth0Users = await readAuth0Users();
    console.log(`总用户数: ${auth0Users.length}`);
    logStream.write(`总用户数: ${auth0Users.length}\n`);

    // 获取所有现有 Logto 用户
    console.log('正在获取现有 Logto 用户列表...');
    const existingUsers = await getAllLogtoUsers();
    // 创建邮箱和手机号的集合
    const migratedEmails = new Set(existingUsers.filter(user => user.primaryEmail).map(user => user.primaryEmail));
    const migratedPhones = new Set(existingUsers.filter(user => user.primaryPhone).map(user => user.primaryPhone));
    
    console.log(`已在 Logto 中存在的用户数: ${existingUsers.length}`);
    console.log(`其中邮箱用户: ${migratedEmails.size}, 手机号用户: ${migratedPhones.size}`);

    // 过滤掉已迁移的用户
    const remainingUsers = auth0Users.filter(user => {
      const emailExists = user.email && migratedEmails.has(user.email);
      const phoneExists = user.phone && migratedPhones.has(user.phone);  // 如果 Auth0 数据中有手机号
      return !emailExists && !phoneExists;
    });
    
    console.log(`\n待迁移用户数: ${remainingUsers.length} (已过滤 ${existingUsers.length} 个已迁移用户)`);
    logStream.write(`\n待迁移用户数: ${remainingUsers.length} (已过滤 ${existingUsers.length} 个已迁移用户)\n`);

    if (remainingUsers.length > 0) {
      console.log('\n待迁移的用户:');
      logStream.write('\n待迁移的用户:\n');
      remainingUsers.forEach(user => {
        console.log(`- ${user.email}`);
        logStream.write(`- ${user.email}\n`);
      });
    }

    let successCount = 0;
    let failureCount = 0;

    // 在开始处理用户前先确保有有效的 token
    await ensureValidToken();

    for (let i = 0; i < remainingUsers.length; i++) {
      const auth0User = remainingUsers[i];
      try {
        // 根据用户信息智能判断
        const exists = await checkUserExists(
          auth0User.email || undefined,
          auth0User.phone || undefined
        );
        if (exists) {
          console.log(`用户已存在（邮箱: ${auth0User.email || '无'}, 手机号: ${auth0User.phone || '无'}），跳过创建`);
          successCount++;
          continue;
        }

        const logtoUser = convertToLogtoUser(auth0User);
        
        // 记录开始迁移
        logStream.write(`[${new Date().toISOString()}] 开始迁移用户 ${auth0User.email}\n`);
        
        // 创建用户
        const result = await createLogtoUser(logtoUser);
        
        // 记录成功
        successCount++;
        const successMessage = `[${new Date().toISOString()}] 成功迁移用户 ${auth0User.email} -> Logto ID: ${result.id}\n`;
        logStream.write(successMessage);
        successStream.write(successMessage);
        console.log(`[${i + 1}/${remainingUsers.length}] 成功迁移用户: ${auth0User.email}`);
        
      } catch (error) {
        if (error instanceof Error && 
           (error.message.includes('JWT verification failed') || 
            error.message.includes('401'))) {
          ACCESS_TOKEN = await refreshAccessToken();
          // 重试当前用户
          i--; // 现在可以修改索引了
          continue;
        }
        // 记录错误
        failureCount++;
        const errorMessage = `[${new Date().toISOString()}] 迁移用户 ${auth0User.email} 失败: ${error instanceof Error ? error.message : '未知错误'}\n`;
        const errorStream = fs.createWriteStream(errorLogPath, { flags: 'a' });
        errorStream.write(errorMessage);
        console.error(`[${i + 1}/${remainingUsers.length}] ${errorMessage}`);
      }

      // 使用配置的延迟时间
      try {
        await new Promise(resolve => setTimeout(resolve, CONFIG.MIGRATION_DELAY));
      } catch (error) {
        console.error('延时出错:', error);
      }
    }

    // 添加迁移统计信息
    const endTime = new Date().toISOString();
    const summary = `
=== 迁移统计 ===
开始时间: ${startTime}
结束时间: ${endTime}
总用户数: ${auth0Users.length}
已迁移用户数: ${existingUsers.length}
本次待迁移数: ${remainingUsers.length}
本次成功数: ${successCount}
本次失败数: ${failureCount}
本次成功率: ${remainingUsers.length > 0 ? ((successCount / remainingUsers.length) * 100).toFixed(2) : '100.00'}%
总体完成率: ${(((existingUsers.length + successCount) / auth0Users.length) * 100).toFixed(2)}%
================
`;
    
    logStream.write(summary);
    console.log(summary);

    // 如果有失败的用户，在控制台显示提示
    if (failureCount > 0) {
      console.log('\n注意：有部分用户迁移失败，请查看 migration-errors.log 获取详细信息');
    }

    logStream.end();
    successStream.end();
    
  } catch (error) {
    console.error('迁移过程发生错误:', error);
  }
}

// 执行迁移
migrateUsers(); 
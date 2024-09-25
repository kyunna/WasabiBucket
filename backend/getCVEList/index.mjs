import pkg from 'pg';
import fs from 'fs';
import { promisify } from 'util';

const { Client } = pkg;
const readFile = promisify(fs.readFile);

const {
  DB_HOST,
  DB_PORT,
  DB_USER,
  DB_PASSWORD,
  DB_NAME
} = process.env;

const connectionString = `postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}`;

export const handler = async (event, context) => {
  const client = new Client({
    connectionString,
    ssl: {
      ca: await readFile('./rds-ca-2019-root.pem'),
      rejectUnauthorized: true
    }
  });

  try {
    console.log('Connecting to the database...');
    await client.connect();
    console.log('Connected successfully.');

    // 페이지네이션 파라미터 처리
    const page = event.queryStringParameters && event.queryStringParameters.page 
      ? parseInt(event.queryStringParameters.page) 
      : 1;
    const limit = 20; // 페이지당 항목 수
    const offset = (page - 1) * limit;

    // 데이터 쿼리 실행 (최근 레코드 순으로 정렬)
    const dataQuery = `
      SELECT 
        c.cve_id, 
        c.last_modified_date,
        c.vulnerability_status, 
        c.updated_at AS cve_updated_at,
        a.updated_at AS analysis_updated_at,
        a.risk_level,
        a.analysis_summary,
        a.affected_products
      FROM 
        cve_data c
      LEFT JOIN 
        analysis_data a ON c.cve_id = a.cve_id
      ORDER BY 
        c.last_modified_date DESC
      LIMIT $1 OFFSET $2
    `;
    console.log(`Executing query: ${dataQuery} with limit ${limit} and offset ${offset}`);
    const dataResult = await client.query(dataQuery, [limit, offset]);

    // 전체 개수 쿼리 실행
    const countQuery = 'SELECT COUNT(*) FROM cve_data';
    const countResult = await client.query(countQuery);
    const totalCount = parseInt(countResult.rows[0].count);

    // 페이지네이션 메타데이터 계산
    const totalPages = Math.ceil(totalCount / limit);
    const hasNextPage = page < totalPages;
    const hasPrevPage = page > 1;

    return {
      statusCode: 200,
      body: JSON.stringify({
        data: dataResult.rows,
        pagination: {
          currentPage: page,
          totalPages: totalPages,
          totalCount: totalCount,
          hasNextPage: hasNextPage,
          hasPrevPage: hasPrevPage
        }
      }),
      headers: { 'Content-Type': 'application/json' }
    };
  } catch (error) {
    console.error('Error executing query:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({
        message: 'Error executing query',
        error: error.message
      }),
      headers: { 'Content-Type': 'application/json' }
    };
  } finally {
    await client.end();
    console.log('Database connection closed.');
  }
};

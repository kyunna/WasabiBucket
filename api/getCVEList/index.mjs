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

    // 페이지네이션 및 검색 파라미터 처리
    const page = event.queryStringParameters?.page ? parseInt(event.queryStringParameters.page) : 1;
    const cveId = event.queryStringParameters?.cveId?.trim();
    const sortBy = event.queryStringParameters?.sortBy;
    const sortOrder = event.queryStringParameters?.sortOrder?.toUpperCase() || 'DESC';
    const limit = 20;
    const offset = (page - 1) * limit;

    // 기본 쿼리 구조
    let dataQuery = `
    SELECT 
      c.cve_id, 
      c.published_date,
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
  `;

    // 검색 조건 추가
    const queryParams = [];
    if (cveId) {
      dataQuery += ` WHERE c.cve_id ILIKE $1`;
      queryParams.push(`%${cveId}%`);
    }

    // 정렬 컬럼 매핑
    const sortableColumns = {
      'published_date': 'c.published_date',
      'last_modified_date': 'c.last_modified_date',
      'analysis_updated_at': 'a.updated_at'
    };
    // 정렬 조건 추가
    const orderByClause = sortBy && sortableColumns[sortBy]
      ? sortBy === 'analysis_updated_at'
        ? `ORDER BY 
            CASE WHEN ${sortableColumns[sortBy]} IS NULL THEN 1 ELSE 0 END,
            ${sortableColumns[sortBy]} ${sortOrder},
            c.last_modified_date DESC`
        : `ORDER BY ${sortableColumns[sortBy]} ${sortOrder}, c.last_modified_date DESC`
      : 'ORDER BY c.last_modified_date DESC';

    // 쿼리에 정렬 조건과 페이지네이션 적용
    dataQuery += ` ${orderByClause} LIMIT $${queryParams.length + 1} OFFSET $${queryParams.length + 2}`;
    queryParams.push(limit, offset);

    console.log(`Executing query: ${dataQuery} with params:`, queryParams);
    const dataResult = await client.query(dataQuery, queryParams);

    // 전체 개수 쿼리
    let countQuery = 'SELECT COUNT(*) FROM cve_data';
    if (cveId) {
      countQuery += ` WHERE cve_id ILIKE $1`;
      const countResult = await client.query(countQuery, [`%${cveId}%`]);
      var totalCount = parseInt(countResult.rows[0].count);
    } else {
      const countResult = await client.query(countQuery);
      var totalCount = parseInt(countResult.rows[0].count);
    }

    // 페이지네이션 메타데이터 계산
    const totalPages = Math.ceil(totalCount / limit);
    const hasNextPage = page < totalPages;
    const hasPrevPage = page > 1;

    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      },
      body: JSON.stringify({
        data: dataResult.rows,
        pagination: {
          currentPage: page,
          totalPages,
          totalCount,
          hasNextPage,
          hasPrevPage
        }
      })
    };
  } catch (error) {
    console.error('Error:', error);
    return {
      statusCode: 500,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      },
      body: JSON.stringify({ message: 'Internal server error' })
    };
  } finally {
    await client.end();
  }
};
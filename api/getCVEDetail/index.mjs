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

    // CVE ID 파라미터 처리
    const cveId = event.pathParameters?.cveId;

    if (!cveId) {
      return {
        statusCode: 400,
        body: JSON.stringify({
          message: 'CVE ID is required',
        }),
        headers: { 'Content-Type': 'application/json' }
      };
    }

    // 데이터 쿼리 실행
    const dataQuery = `
      SELECT 
        c.cve_id,
        a.analysis_summary,
        a.recommendation,
        a.risk_level,
        a.vulnerability_type,
        a.affected_systems,
        a.affected_products AS analysis_affected_products,
        a.technical_details,
        a.created_at,
        a.updated_at,
        c.published_date,
        c.last_modified_date,
        c.vulnerability_status,
        c.description,
        c.cvss_v3_vector,
        c.cvss_v3_base_score,
        c.cvss_v3_base_severity,
        c.cvss_v4_vector,
        c.cvss_v4_base_score,
        c.cvss_v4_base_severity,
        c.affected_products AS cve_affected_products,
        c.reference_links,
        c.cwe_ids
      FROM 
        cve_data c
      LEFT JOIN 
        analysis_data a ON c.cve_id = a.cve_id
      WHERE 
        c.cve_id = $1
    `;
    console.log(`Executing query: ${dataQuery}, CVE ID: ${cveId}`);
    const dataResult = await client.query(dataQuery, [cveId]);

    if (dataResult.rows.length === 0) {
      return {
        statusCode: 404,
        body: JSON.stringify({
          message: 'CVE not found',
        }),
        headers: { 'Content-Type': 'application/json' }
      };
    }

    return {
      statusCode: 200,
      body: JSON.stringify({
        result: dataResult.rows[0],
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
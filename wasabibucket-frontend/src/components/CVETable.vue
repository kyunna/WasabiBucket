<template>
  <div>
    <h1>CVE Data</h1>
    <table>
      <thead>
        <tr>
          <th>CVE ID</th>
          <th>Description</th>
          <th>CVSS V3 Score</th>
          <th>CVSS V3 Severity</th>
          <th>CVSS V4 Score</th>
          <th>CVSS V4 Severity</th>
          <th>Affected Products</th>
          <th>CWE IDs</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="cve in cveData" :key="cve.cve_id">
          <td>{{ cve.cve_id }}</td>
          <td>{{ cve.description }}</td>
          <td>{{ cve.cvss_v3_base_score }}</td>
          <td>{{ cve.cvss_v3_base_severity }}</td>
          <td>{{ cve.cvss_v4_base_score }}</td>
          <td>{{ cve.cvss_v4_base_severity }}</td>
          <td>{{ cve.affected_products.join(', ') }}</td>
          <td>{{ cve.cwe_ids.join(', ') }}</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script>
import axios from 'axios';

export default {
  data() {
    return {
      cveData: []
    };
  },
  created() {
    this.fetchCVEData();
  },
  methods: {
    async fetchCVEData() {
      try {
        const response = await axios.get('http://localhost:8080/api/cve_data');
        this.cveData = response.data;
      } catch (error) {
        console.error('Error fetching CVE data:', error);
      }
    }
  }
};
</script>

<style scoped>
table {
  width: 100%;
  border-collapse: collapse;
}

th, td {
  border: 1px solid #ddd;
  padding: 8px;
}

th {
  background-color: #f2f2f2;
  text-align: left;
}
</style>
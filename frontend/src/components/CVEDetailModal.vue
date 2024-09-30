<template>
  <div v-if="show" class="modal-overlay" @click="closeModal">
    <div class="modal-content" @click.stop>
      <div class="modal-header">
        <h2>{{ cveDetail ? `${cveDetail.cve_id} 상세 정보` : 'CVE 상세 정보' }}</h2>
        <button class="close-button" @click="closeModal">&times;</button>
      </div>
      <div v-if="cveDetail" class="modal-body">
        <section>
          <h3>분석 내용</h3>
          <table class="unified-table">
            <colgroup>
              <col style="width: 16.66%;">
              <col style="width: 16.66%;">
              <col style="width: 16.66%;">
              <col style="width: 16.66%;">
              <col style="width: 16.66%;">
              <col style="width: 16.66%;">
            </colgroup>
            <tr>
              <th>CVE ID</th>
              <td>{{ cveDetail.cve_id }}</td>
              <th>위험도</th>
              <td>
                <img :src="getRiskLevelIcon(cveDetail.risk_level)" :alt="getRiskLevel(cveDetail.risk_level)" class="risk-icon">
                {{ getRiskLevel(cveDetail.risk_level) }}
              </td>
              <th>취약점 분류</th>
              <td>{{ cveDetail.vulnerability_type || '-' }}</td>
            </tr>
            <tr>
              <th>최초 분석일</th>
              <td colspan="2">{{ formatDate(cveDetail.created_at) }}</td>
              <th>최종 수정일</th>
              <td colspan="2">{{ formatDate(cveDetail.updated_at) }}</td>
            </tr>
            <tr>
              <th>영향받는 시스템</th>
              <td colspan="5">{{ cveDetail.affected_systems || '-' }}</td>
            </tr>
            <tr>
              <th>영향받는 제품</th>
              <td colspan="5">{{ formatAffectedProducts(cveDetail.analysis_affected_products) }}</td>
            </tr>
            <tr>
              <th>분석 요약</th>
              <td colspan="5">{{ cveDetail.analysis_summary || '-' }}</td>
            </tr>
            <tr>
              <th>권장사항</th>
              <td colspan="5">{{ cveDetail.recommendation || '-' }}</td>
            </tr>
            <tr>
              <th>기술적 세부사항</th>
              <td colspan="5">{{ cveDetail.technical_details || '-' }}</td>
            </tr>
          </table>
        </section>

        <section>
          <h3>CVE 정보</h3>
          <table class="unified-table">
            <colgroup>
              <col style="width: 16.66%;">
              <col style="width: 16.66%;">
              <col style="width: 16.66%;">
              <col style="width: 16.66%;">
              <col style="width: 16.66%;">
              <col style="width: 16.66%;">
            </colgroup>
            <tr>
              <th>발행일</th>
              <td>{{ formatDate(cveDetail.published_date) }}</td>
              <th>최종 수정일</th>
              <td>{{ formatDate(cveDetail.last_modified_date) }}</td>
              <th>취약점 상태</th>
              <td>{{ cveDetail.vulnerability_status || '-' }}</td>
            </tr>
            <tr>
              <th>설명(영문)</th>
              <td colspan="5">{{ cveDetail.description }}</td>
            </tr>
            <tr>
              <th>CVSS v3 Vector</th>
              <td colspan="5">{{ cveDetail.cvss_v3_vector || '-' }}</td>
            </tr>
            <tr>
              <th>CVSS v3 Score</th>
              <td colspan="2">{{ cveDetail.cvss_v3_base_score || '-' }}</td>
              <th >CVSS v3 Severity</th>
              <td colspan="3">{{ cveDetail.cvss_v3_base_severity || '-' }}</td>
            </tr>
            <tr>
              <th>CVSS v4 Vector</th>
              <td colspan="5">{{ cveDetail.cvss_v4_vector || '-' }}</td>
            </tr>
            <tr>
              <th>CVSS v4 Score</th>
              <td colspan="2">{{ cveDetail.cvss_v4_base_score || '-' }}</td>
              <th>CVSS v4 Severity</th>
              <td colspan="3">{{ cveDetail.cvss_v4_base_severity || '-' }}</td>
            </tr>
            <tr>
              <th>CPE</th>
              <td colspan="5">{{ formatAffectedProducts(cveDetail.cve_affected_products) }}</td>
            </tr>
            <tr>
              <th>CWE</th>
              <td colspan="5">{{ formatCWEIds(cveDetail.cwe_ids) }}</td>
            </tr>
            <tr>
              <th>Reference Link</th>
              <td colspan="5" v-html="formatReferenceLinks(cveDetail.reference_links)"></td>
            </tr>
          </table>
        </section>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, watch } from 'vue';
import axios from 'axios';

export default {
  props: {
    show: Boolean,
    cveId: String,
  },
  emits: ['close'],
  setup(props, { emit }) {
    const cveDetail = ref(null);

    const fetchCVEDetail = async () => {
      try {
        const response = await axios.get(`https://k07yvmvs4c.execute-api.ap-northeast-2.amazonaws.com/cve/${props.cveId}`);
        cveDetail.value = response.data.result;  // 여기를 수정
      } catch (error) {
        console.error('CVE 상세 정보를 불러오는 중 오류가 발생했습니다:', error);
      }
    };

    watch(() => props.show, (newValue) => {
      if (newValue && props.cveId) {
        fetchCVEDetail();
      }
    });

    const closeModal = () => {
      emit('close');
    };

    const formatDate = (dateString) => {
      if (!dateString) return '-';
      const date = new Date(dateString);
      return date.toLocaleString('ko-KR', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
      }).replace(/\. /g, '.').replace(',', '').replace(/\.(?=[0-9]{2}:)/, ' ');
    };

    const getRiskLevel = (level) => {
      const levels = {
        '0': 'LOW',
        '1': 'MEDIUM',
        '2': 'HIGH'
      };
      return levels[level] || '알 수 없음';
    };

    const getRiskLevelIcon = (level) => {
      const icons = {
        '0': require('@/assets/risk_low.svg'),
        '1': require('@/assets/risk_medium.svg'),
        '2': require('@/assets/risk_high.svg')
      };
      return icons[level] || require('@/assets/risk_unknown.svg');
    };

    const formatAffectedProducts = (products) => {
      if (!products || products.length === 0) return '-';
      return products.join(', ');
    };

    const formatReferenceLinks = (links) => {
      if (!links || links.length === 0) return '-';
      return links.map(link => `<a href="${link}" target="_blank">${link}</a>`).join('<br>');
    };

    const formatCWEIds = (cweIds) => {
      if (!cweIds || cweIds.length === 0) return '-';
      return cweIds.join(', ');
    };

    return {
      cveDetail,
      closeModal,
      formatDate,
      getRiskLevel,
      getRiskLevelIcon,
      formatAffectedProducts,
      formatReferenceLinks,
      formatCWEIds,
    };
  }
}
</script>

<style scoped>
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background-color: rgba(0, 0, 0, 0.5);
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: 1000;
}

.modal-content {
  background-color: white;
  padding: 20px;
  border-radius: 8px;
  max-width: 960px; /* 800px에서 20% 증가 */
  width: 95%; /* 90%에서 95%로 증가 */
  max-height: 90vh;
  overflow-y: auto;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.close-button {
  background: none;
  border: none;
  font-size: 24px;
  cursor: pointer;
}

.modal-body {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

table {
  width: 100%;
  border-collapse: collapse;
}

th, td {
  border: 1px solid #ddd;
  padding: 8px;
  text-align: left;
}

th {
  background-color: #f2f2f2;
  width: 30%;
}

h3 {
  margin-top: 0;
}

/* 추가 스타일 */
.modal-body table {
  table-layout: fixed;
}

.modal-body th {
  width: 15%;
}

.modal-body td {
  width: 18%;
}

.modal-body td[colspan="5"] {
  width: 85%;
}

.modal-body td[colspan="3"] {
  width: 51%;
}

.info-table, .detail-table {
  width: 100%;
  border-collapse: collapse;
  margin-bottom: 10px;
}

.info-table th, .info-table td {
  border: 1px solid #b0c4ff;
  padding: 8px;
  text-align: left;
  width: 16.66%; /* 6개의 열을 균등하게 분배 */
}

.detail-table th {
  width: 180px; /* 고정된 크기로 설정 */
  background-color: #648eeb;
  color: white;
}

.detail-table td {
  width: auto; /* 남은 공간을 자동으로 채우도록 설정 */
}

/* CVE 정보 섹션의 detail-table에 대한 추가 스타일 */
.detail-table td[colspan="3"] {
  width: calc(100% - 180px); /* th의 너비를 제외한 나머지 */
}

.info-table th, .detail-table th {
  background-color: #648eeb;
  color: white;
}

/* 기존의 .modal-body table 관련 스타일은 제거 또는 주석 처리 */

.unified-table {
  width: 100%;
  border-collapse: collapse;
  margin-bottom: 10px;
  table-layout: fixed;
}

.unified-table th, .unified-table td {
  border: 1px solid #b0c4ff;
  padding: 8px;
  text-align: left;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: normal; /* 'nowrap'에서 'normal'로 변경 */
  word-wrap: break-word; /* 긴 단어의 줄바꿈 허용 */
}

.unified-table th {
  background-color: #648eeb;
  color: white;
}

/* col-* 클래스 제거 (colgroup으로 대체) */

/* 긴 내용을 위한 스타일 */
.unified-table td[colspan="5"],
.unified-table td[colspan="4"],
.unified-table td[colspan="3"],
.unified-table td.col-10 {
  white-space: normal;
  word-wrap: break-word;
}

/* 추가 스타일 */
.unified-table tr {
  display: table-row;
}

.unified-table td:empty::after {
  content: "\00a0"; /* 빈 셀에 공백 문자 추가 */
}

.risk-icon {
  width: 20px;
  height: 20px;
  vertical-align: middle;
  margin-right: 5px;
}
</style>
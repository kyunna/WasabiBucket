<template>
  <el-dialog
    v-model="dialogVisible"
    :title="cveDetail ? `${cveDetail.cve_id} 상세 정보` : 'CVE 상세 정보'"
    width="80%"
    :before-close="handleClose"
  >
    <div v-if="cveDetail" class="modal-body">
      <el-tabs>
        <el-tab-pane label="분석 내용">
          <el-descriptions :column="3" border>
            <el-descriptions-item label="CVE ID" :label-style="labelStyle">{{ cveDetail.cve_id }}</el-descriptions-item>
            <el-descriptions-item label="위험도" :label-style="labelStyle">
              <el-image
                :src="getRiskLevelIcon(cveDetail.risk_level)"
                :alt="getRiskLevel(cveDetail.risk_level)"
                style="width: 20px; height: 20px; vertical-align: middle;"
              />
              {{ getRiskLevel(cveDetail.risk_level) }}
            </el-descriptions-item>
            <el-descriptions-item label="취약점 분류" :label-style="labelStyle">{{ cveDetail.vulnerability_type || '-' }}</el-descriptions-item>
            <el-descriptions-item label="최초 분석일" :label-style="labelStyle">{{ formatDateTime(cveDetail.created_at) }}</el-descriptions-item>
            <el-descriptions-item label="최종 분석일" :span="2" :label-style="labelStyle">{{ formatDateTime(cveDetail.updated_at) }}</el-descriptions-item>
            <el-descriptions-item label="영향받는 시스템" :span="3" :label-style="labelStyle">{{ cveDetail.affected_systems || '-' }}</el-descriptions-item>
            <el-descriptions-item label="영향받는 제품" :span="3" :label-style="labelStyle">{{ formatAffectedProducts(cveDetail.analysis_affected_products) }}</el-descriptions-item>
            <el-descriptions-item label="분석 요약" :span="3" :label-style="labelStyle">{{ cveDetail.analysis_summary || '-' }}</el-descriptions-item>
            <el-descriptions-item label="권장사항" :span="3" :label-style="labelStyle">{{ cveDetail.recommendation || '-' }}</el-descriptions-item>
            <el-descriptions-item label="기술적 세부사항" :span="3" :label-style="labelStyle">{{ cveDetail.technical_details || '-' }}</el-descriptions-item>
          </el-descriptions>
        </el-tab-pane>
        
        <el-tab-pane label="CVE 정보">
          <el-descriptions :column="3" border>
            <el-descriptions-item label="발행일" :label-style="labelStyle">{{ formatDateTime(cveDetail.published_date) }}</el-descriptions-item>
            <el-descriptions-item label="최종 수정일" :label-style="labelStyle">{{ formatDateTime(cveDetail.last_modified_date) }}</el-descriptions-item>
            <el-descriptions-item label="취약점 상태" :label-style="labelStyle">{{ cveDetail.vulnerability_status || '-' }}</el-descriptions-item>
            <el-descriptions-item label="설명(영문)" :span="3" :label-style="labelStyle">{{ cveDetail.description }}</el-descriptions-item>
            <el-descriptions-item label="CVSS v3 Vector" :span="3" :label-style="labelStyle">{{ cveDetail.cvss_v3_vector || '-' }}</el-descriptions-item>
            <el-descriptions-item label="CVSS v3 Score" :label-style="labelStyle">{{ cveDetail.cvss_v3_base_score || '-' }}</el-descriptions-item>
            <el-descriptions-item label="CVSS v3 Severity" :span="2" :label-style="labelStyle">{{ cveDetail.cvss_v3_base_severity || '-' }}</el-descriptions-item>
            <el-descriptions-item label="CVSS v4 Vector" :span="3" :label-style="labelStyle">{{ cveDetail.cvss_v4_vector || '-' }}</el-descriptions-item>
            <el-descriptions-item label="CVSS v4 Score" :label-style="labelStyle">{{ cveDetail.cvss_v4_base_score || '-' }}</el-descriptions-item>
            <el-descriptions-item label="CVSS v4 Severity" :span="2" :label-style="labelStyle">{{ cveDetail.cvss_v4_base_severity || '-' }}</el-descriptions-item>
            <el-descriptions-item label="CPE" :span="3" :label-style="labelStyle">{{ formatAffectedProducts(cveDetail.cve_affected_products) }}</el-descriptions-item>
            <el-descriptions-item label="CWE" :span="3" :label-style="labelStyle">{{ formatCWEIds(cveDetail.cwe_ids) }}</el-descriptions-item>
            <el-descriptions-item label="Reference Link" :span="3" :label-style="labelStyle">
              <div v-html="formatReferenceLinks(cveDetail.reference_links)"></div>
            </el-descriptions-item>
          </el-descriptions>
        </el-tab-pane>
      </el-tabs>
    </div>
  </el-dialog>
</template>

<script>
import { ref, watch, computed } from 'vue';
import axios from 'axios';

export default {
  props: {
    show: Boolean,
    cveId: String,
  },
  emits: ['update:show'],
  setup(props, { emit }) {
    const cveDetail = ref(null);
    const dialogVisible = ref(props.show);

    watch(() => props.show, (newValue) => {
      dialogVisible.value = newValue;
      if (newValue && props.cveId) {
        fetchCVEDetail();
      }
    });

    watch(dialogVisible, (newValue) => {
      emit('update:show', newValue);
    });

    const fetchCVEDetail = async () => {
      try {
        const response = await axios.get(`https://k07yvmvs4c.execute-api.ap-northeast-2.amazonaws.com/cve/${props.cveId}`);
        cveDetail.value = response.data.result;
      } catch (error) {
        console.error('CVE 상세 정보를 불러오는 중 오류가 발생했습니다:', error);
      }
    };

    const handleClose = (done) => {
      done();
    };

    const formatDate = (dateString) => {
      if (!dateString) return '-'
      const date = new Date(dateString)
      const year = date.toLocaleDateString('en-US', { year: 'numeric' })
      const month = date.toLocaleDateString('en-US', { month: '2-digit' })
      const day = date.toLocaleDateString('en-US', { day: '2-digit' })

      return `${year}-${month}-${day}`
    }

    const formatDateTime = (dateString) => {
      if (!dateString) return '-'
      const date = new Date(dateString)
      const year = date.toLocaleString('en-US', { year: 'numeric' })
      const month = date.toLocaleString('en-US', { month: '2-digit' })
      const day = date.toLocaleString('en-US', { day: '2-digit' })
      const hour = date.toLocaleString('en-US', { hour: '2-digit', hour12: false })
      const minute = date.getMinutes().toString().padStart(2, '0')
      const second = date.getSeconds().toString().padStart(2, '0')

      return `${year}-${month}-${day} ${hour}:${minute}:${second}`
    }

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

    const labelStyle = computed(() => ({
      width: '150px',
      minWidth: '150px',
      maxWidth: '150px',
      backgroundColor: '#f0f0f0',
    }));

    return {
      cveDetail,
      dialogVisible,
      handleClose,
      formatDate,
      getRiskLevel,
      getRiskLevelIcon,
      formatAffectedProducts,
      formatReferenceLinks,
      formatCWEIds,
      labelStyle,
      formatDateTime,
    };
  }
}
</script>

<style scoped>
.el-descriptions {
  margin-bottom: 20px;
}

:deep(.el-descriptions__label) {
  width: 150px !important;
  min-width: 150px !important;
  max-width: 150px !important;
  background-color: #f0f0f0 !important;
}

:deep(.el-descriptions__content) {
  word-break: break-word;
}
</style>
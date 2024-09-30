<template>
  <div>
    <h1>CVE List</h1>
    <el-table
      v-loading="loading"
      :data="cves"
      style="width: 100%"
      @row-click="showDetail"
    >
      <el-table-column prop="published_date" label="등록일" width="120">
        <template #default="scope">
          {{ formatDate(scope.row.published_date) }}
        </template>
      </el-table-column>
      <el-table-column prop="last_modified_date" label="갱신일" width="120">
        <template #default="scope">
          {{ formatDate(scope.row.last_modified_date) }}
        </template>
      </el-table-column>
      <el-table-column prop="cve_id" label="CVE ID" width="140" />
      <el-table-column prop="vulnerability_status" label="상태" width="100" />
      <el-table-column prop="analysis_summary" label="분석 요약" min-width="200">
        <template #default="scope">
          <el-tooltip :content="scope.row.analysis_summary" placement="top" :hide-after="0">
            <span>{{ truncateText(scope.row.analysis_summary, 100) }}</span>
          </el-tooltip>
        </template>
      </el-table-column>
      <el-table-column prop="risk_level" label="위험도" width="80">
        <template #default="scope">
          <el-tooltip :content="getRiskLevel(scope.row.risk_level)" placement="top">
            <el-image
              :src="getRiskLevelIcon(scope.row.risk_level)"
              :alt="getRiskLevel(scope.row.risk_level)"
              style="width: 20px; height: 20px;"
            />
          </el-tooltip>
        </template>
      </el-table-column>
      <el-table-column prop="affected_products" label="영향받는 제품" min-width="150">
        <template #default="scope">
          <el-tooltip :content="scope.row.affected_products?.join(', ')" placement="top" :hide-after="0">
            <span>{{ formatAffectedProducts(scope.row.affected_products) }}</span>
          </el-tooltip>
        </template>
      </el-table-column>
      <el-table-column prop="analysis_updated_at" label="최종 분석일" width="160">
        <template #default="scope">
          {{ formatDateTime(scope.row.analysis_updated_at) }}
        </template>
      </el-table-column>
      <el-table-column label="분석" width="80">
        <template #default="scope">
          <el-button @click.stop="requestAnalysis(scope.row.cve_id)" type="primary" size="small" :icon="scope.row.analysis_summary ? 'Refresh' : 'VideoPlay'" />
        </template>
      </el-table-column>
    </el-table>

    <div class="pagination-container">
      <el-pagination
        v-model:current-page="currentPage"
        :page-size="20"
        :total="pagination?.totalCount || 0"
        @current-change="handleCurrentChange"
        layout="total, prev, pager, next, jumper"
      />
    </div>

    <CVEDetailModal 
      :show="showModal"
      :cveId="selectedCveId"
      @close="closeModal"
    />
  </div>
</template>

<script>
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import axios from 'axios'
import CVEDetailModal from './CVEDetailModal.vue'

export default {
  components: {
    CVEDetailModal
  },
  setup() {
    const cves = ref([])
    const pagination = ref(null)
    const showModal = ref(false)
    const selectedCveId = ref(null)
    const currentPage = ref(1)
    const loading = ref(false)

    const fetchCVEs = async (page = 1) => {
      loading.value = true
      try {
        const response = await axios.get(`https://k07yvmvs4c.execute-api.ap-northeast-2.amazonaws.com/cve?page=${page}`)
        cves.value = response.data.data
        pagination.value = response.data.pagination
      } catch (error) {
        console.error('CVE 데이터를 불러오는 중 오류가 발생했습니다:', error)
        ElMessage.error('데이터를 불러오는 데 실패했습니다.')
      } finally {
        loading.value = false
      }
    }

    const handleCurrentChange = (val) => {
      fetchCVEs(val)
    }

    const formatDate = (dateString) => {
      if (!dateString) return '-'
      const date = new Date(dateString)
      return date.toLocaleDateString('ko-KR', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit'
      }).replace(/\. /g, '-').replace(',', '').replace(/\.$/, '')
    }

    const formatDateTime = (dateString) => {
      if (!dateString) return '-'
      const date = new Date(dateString)
      return date.toLocaleString('ko-KR', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
      }).replace(/\. /g, '-').replace(',', '').replace(/-/g, ' ')
    }

    const truncateText = (text, length) => {
      if (!text) return '-'
      return text.length > length ? text.substring(0, length) + '...' : text
    }

    const formatAffectedProducts = (products) => {
      if (!products) return '-'
      if (products.length === 0) return '-'
      if (products.length === 1) return products[0]
      return `${products[0]} 외`
    }

    const requestAnalysis = async (cveId) => {
      try {
        await axios.post('https://k07yvmvs4c.execute-api.ap-northeast-2.amazonaws.com/analyze', {
          cveId: cveId
        })
        ElMessage.success('분석 요청이 성공적으로 전송되었습니다.')
      } catch (error) {
        console.error('분석 요청 중 오류가 발생했습니다:', error)
        ElMessage.error('분석 요청 중 오류가 발생했습니다.')
      }
    }

    const showDetail = (row) => {
      selectedCveId.value = row.cve_id
      showModal.value = true
    }

    const closeModal = () => {
      showModal.value = false
      selectedCveId.value = null
    }

    const getRiskLevel = (level) => {
      const levels = {
        '0': 'LOW',
        '1': 'MEDIUM',
        '2': 'HIGH'
      }
      return levels[level] || '알 수 없음'
    }

    const getRiskLevelIcon = (level) => {
      const icons = {
        '0': require('@/assets/risk_low.svg'),
        '1': require('@/assets/risk_medium.svg'),
        '2': require('@/assets/risk_high.svg')
      }
      return icons[level] || require('@/assets/risk_unknown.svg')
    }

    onMounted(() => fetchCVEs())

    return {
      cves,
      pagination,
      showModal,
      selectedCveId,
      currentPage,
      loading,
      formatDate,
      formatDateTime,
      truncateText,
      formatAffectedProducts,
      requestAnalysis,
      showDetail,
      closeModal,
      handleCurrentChange,
      getRiskLevel,
      getRiskLevelIcon
    }
  }
}
</script>

<style scoped>
.pagination-container {
  margin-top: 20px;
  display: flex;
  justify-content: center;
}
</style>
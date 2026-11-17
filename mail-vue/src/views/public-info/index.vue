<template>
  <div class="info-page">
    <header class="site-header">
      <RouterLink class="brand" to="/about">
        <img :src="logo" alt="" />
        <span>Neutbo Mail</span>
      </RouterLink>
      <nav aria-label="页面导航">
        <RouterLink to="/about">关于</RouterLink>
        <RouterLink to="/privacy">隐私说明</RouterLink>
        <RouterLink class="login-link" to="/login">登录邮箱</RouterLink>
      </nav>
    </header>

    <main>
      <div class="preview-notice" role="note">测试预览 · 内容尚未正式发布</div>
      <template v-if="page === 'about'">
        <section class="hero">
          <div class="eyebrow"><span></span> NEUTBO MAIL</div>
          <h1>让每封邮件，<br /><span>都有清晰的归处。</span></h1>
          <p>Neutbo Mail 是一个在线邮箱，用于收发邮件、管理消息和附件，让日常沟通更简单。</p>
          <div class="actions">
            <RouterLink class="primary" to="/login">打开邮箱 <span aria-hidden="true">↗</span></RouterLink>
            <RouterLink class="secondary" to="/privacy">了解隐私说明</RouterLink>
          </div>
        </section>
        <section class="features" aria-label="产品功能">
          <article><span>01</span><h2>收发邮件</h2><p>在一个地方查看、撰写和管理你的邮件。</p></article>
          <article><span>02</span><h2>整理消息</h2><p>使用收件箱、已发送、草稿和星标整理重要内容。</p></article>
          <article><span>03</span><h2>附件与沟通</h2><p>随邮件收发附件，让信息和文件留在一起。</p></article>
        </section>
      </template>
      <article v-else class="policy">
        <div class="eyebrow"><span></span> PRIVACY</div>
        <h1>隐私说明</h1>
        <p class="lead">这是一份供核实的预览稿，尚未作为正式隐私政策发布。</p>
        <section><h2>运营者与联系方法</h2><p>Neutbo Mail 由个人运营。如有账号或个人信息相关问题，可联系 <a href="mailto:support@neutbo.com">support@neutbo.com</a>。</p></section>
        <section><h2>我们处理的信息</h2><p>为了提供邮箱服务，系统会处理账号信息、邮箱地址、邮件内容、附件以及发件人和收件人等相关信息。注册验证或账号恢复可能使用你验证过的外部邮箱。</p><p>如果你选择使用 Google 登录，应用会请求基本身份信息，用于登录或绑定账号。实际保存的字段和使用方式将在正式发布前核实。</p></section>
        <section><h2>服务提供商</h2><p>Neutbo Mail 使用 Cloudflare 提供运行、数据存储和邮件路由服务；验证邮件可能由已配置的发信服务发送。你启用邮件转发或其他可选功能后，信息可能发送到相应的目标。</p></section>
        <section><h2>保存与删除</h2><p>当前正式站没有启用按天数自动清理普通邮件。手动删除、服务日志和备份的保存与删除方式仍需进一步核实；账号删除与恢复流程尚在测试中。</p><p>你可以联系支持邮箱咨询邮件或账号的处理方式。</p></section>
        <section><h2>待核实事项</h2><p>正式发布前需补全数据保存期限、备份处理方式、实际服务提供商以及用户请求处理流程。此页面不能作为正式审核材料。</p></section>
      </article>
    </main>
    <footer><span>© Neutbo Mail</span><a href="mailto:support@neutbo.com">support@neutbo.com</a></footer>
  </div>
</template>

<script setup>
defineProps({page: {type: String, required: true}})
const logo = `${import.meta.env.BASE_URL}neutbo-bird-v1.svg`
</script>

<style scoped>
.info-page{min-height:100vh;background:#f7f9fc;color:#182435;font-family:Inter,"Segoe UI","Microsoft YaHei",sans-serif}
.site-header,main,footer{max-width:1120px;margin:auto}
.site-header{display:flex;align-items:center;justify-content:space-between;padding:26px 28px}
.brand{display:flex;align-items:center;gap:11px;color:#182435;text-decoration:none;font-size:19px;font-weight:750;letter-spacing:-.03em}
.brand img{width:37px;height:37px;object-fit:contain}
nav{display:flex;align-items:center;gap:28px}nav a{color:#536176;text-decoration:none;font-size:14px;font-weight:600}nav a:hover,.policy a:hover{color:#1766cc}
nav .login-link{border:1px solid #d6deeb;border-radius:999px;padding:10px 18px;color:#24364d;background:#fff}
main{padding:0 28px}.preview-notice{padding:12px 16px;border:1px solid #e7d7b2;border-radius:10px;background:#fffaf0;color:#765a20;font-size:13px}
.hero{padding:112px 0 90px;max-width:760px}.eyebrow{display:flex;align-items:center;gap:9px;color:#356fbc;letter-spacing:.18em;font-size:12px;font-weight:750}.eyebrow span{width:7px;height:7px;background:#4b8ee8;border-radius:50%}
h1{margin:22px 0;color:#182435;font-size:clamp(38px,6vw,68px);line-height:1.16;letter-spacing:-.055em}h1 span{color:#5a83b7}.hero>p{max-width:570px;font-size:17px;line-height:1.9;color:#68778b}
.actions{display:flex;gap:12px;margin-top:34px;flex-wrap:wrap}.actions a{padding:13px 20px;border-radius:11px;text-decoration:none;font-size:14px;font-weight:650}.primary{background:#1e69cf;color:white}.primary span{margin-left:12px}.secondary{border:1px solid #dbe2ed;background:#fff;color:#3f536b}
.features{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;padding-bottom:90px}.features article{min-height:170px;padding:25px;border:1px solid #e5ebf3;border-radius:18px;background:#fff}.features span{font-size:12px;color:#6795cb;font-weight:700}.features h2{font-size:17px;margin:23px 0 9px}.features p,.policy p{color:#68778b;font-size:14px;line-height:1.85}
.policy{max-width:760px;padding:80px 0 90px}.policy h1{font-size:48px}.policy .lead{font-size:16px}.policy section{margin-top:35px}.policy h2{font-size:19px}.policy a{color:#1766cc}
footer{border-top:1px solid #e5ebf3;padding:25px 28px;display:flex;justify-content:space-between;gap:20px;font-size:13px;color:#8491a3}footer a{color:#72849b;text-decoration:none}
@media(max-width:650px){.site-header{align-items:flex-start;gap:18px}.brand span{font-size:16px}nav{gap:12px;flex-wrap:wrap;justify-content:flex-end}nav a{font-size:12px}nav .login-link{padding:8px 12px}.hero{padding:75px 0 60px}.features{grid-template-columns:1fr}.features article{min-height:0}.policy{padding:60px 0}.policy h1{font-size:38px}footer{flex-wrap:wrap}}
</style>

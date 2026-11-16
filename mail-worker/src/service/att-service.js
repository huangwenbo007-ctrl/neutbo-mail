import orm from '../entity/orm';
import { att } from '../entity/att';
import { and, eq, isNull, inArray, desc } from 'drizzle-orm';
import r2Service from './r2-service';
import constant from '../const/constant';
import fileUtils from '../utils/file-utils';
import { attConst } from '../const/entity-const';
import { parseHTML } from 'linkedom';
import { v4 as uuidv4 } from 'uuid';
import domainUtils from '../utils/domain-uitls';
import settingService from "./setting-service";
import { withObjectLocks } from './account-deletion-state';

const attService = {

	async addAtt(c, attachments) {
		return this.withAttachmentLocks(c, attachments.map(item => item.key), async () => {
			for (let attachment of attachments) {
				let metadate = {
					contentType: attachment.mimeType,
				}
				if (!attachment.contentId) {
					metadate.contentDisposition = `attachment;filename=${attachment.filename}`
				} else {
					metadate.contentDisposition = `inline;filename=${attachment.filename}`
					metadate.cacheControl = `max-age=259200`
				}
				await r2Service.putObj(c, attachment.key, attachment.content, metadate);
			}

			await orm(c).insert(att).values(attachments).run();
		});
	},

	async withAttachmentLocks(c, keys, action) {
		const storageType = await r2Service.storageType(c);
		return withObjectLocks(c.env.db, storageType, keys, crypto.randomUUID(), Math.floor(Date.now() / 1000), action);
	},

	list(c, params, userId) {
		const { emailId } = params;

		return orm(c).select().from(att).where(
			and(
				eq(att.emailId, emailId),
				eq(att.userId, userId),
				eq(att.type, attConst.type.ATT),
				isNull(att.contentId)
			)
		).all();
	},

	async toImageUrlHtml(c, content) {

		const { r2Domain } = await settingService.query(c);

		const { document } = parseHTML(content);

		const images = Array.from(document.querySelectorAll('img'));

		let imageDataList = [];

		for (const img of images) {

			//邮件正文base64图片转cid附件
			const src = img.getAttribute('src');
			if (src && src.startsWith('data:image')) {
				const file = fileUtils.base64ToFile(src);
				const buff = await file.arrayBuffer();
				const cid = uuidv4().replace(/-/g, '');
				const key = constant.ATTACHMENT_PREFIX + await fileUtils.getBuffHash(buff) + fileUtils.getExtFileName(file.name);

				img.setAttribute('src', 'cid:' + cid);

				const attData = {};
				attData.key = key;
				attData.filename = file.name;
				attData.mimeType = file.type;
				attData.size = file.size;
				attData.buff = buff;
				attData.content = fileUtils.base64ToDataStr(src);
				attData.contentId = cid;

				imageDataList.push(attData);
			}

			//邮件正文站内图片转cid附件
			if (src && (src.startsWith(domainUtils.toOssDomain(r2Domain)) || src.startsWith('attachments/'))) {

				const cid = uuidv4().replace(/-/g, '')
				img.setAttribute('src', 'cid:' + cid);

				const attData = {};

				if (src.startsWith(domainUtils.toOssDomain(r2Domain))) {
					attData.key = src.replace(domainUtils.toOssDomain(r2Domain) + '/','');
				}

				if (src.startsWith('attachments/')) {
					attData.key = src;
				}

				attData.contentId = cid;
				attData.type = attConst.type.EMBED;
				imageDataList.push(attData);

			}

			const hasInlineWidth = img.hasAttribute('width');
			const style = img.getAttribute('style') || '';
			const hasStyleWidth = /(^|\s)width\s*:\s*[^;]+/.test(style);

			if (!hasInlineWidth && !hasStyleWidth) {
				const newStyle = (style ? style.trim().replace(/;$/, '') + '; ' : '') + 'max-width: 100%;';
				img.setAttribute('style', newStyle);
			}
		}

		//查询已有内嵌url图片信息
		const keys = [...new Set(imageDataList.filter(item => !item.content).map(item => item.key))];
		const dbImageList  = await this.selectOneByKeys(c, keys);

		//设置给当前附件
		await Promise.all(imageDataList.map(async image => {
			if (image.content) {
				return;
			}

			const dbImage = dbImageList.find(dbImage => image.key === dbImage.key);
			if (!dbImage) {
				return;
			}

			image.size = dbImage.size;
			image.filename = dbImage.filename;
			image.mimeType = dbImage.mimeType;
			image.contentType = dbImage.mimeType;

			const obj = await r2Service.getObj(c, image.key);
			if (!obj) {
				return;
			}

			image.content = obj instanceof ArrayBuffer ? obj : await obj.arrayBuffer();
		}))

		imageDataList = imageDataList.filter(image => image.content);

		return { imageDataList, html: document.toString() };
	},

	async saveSendAtt(c, attList, userId, accountId, emailId) {

		const attDataList = [];

		for (let att of attList) {
			att.buff = fileUtils.base64ToUint8Array(att.content);
			att.key = constant.ATTACHMENT_PREFIX + await fileUtils.getBuffHash(att.buff) + fileUtils.getExtFileName(att.filename);
			const attData = { userId, accountId, emailId };
			attData.key = att.key;
			attData.size = att.buff.length;
			attData.filename = att.filename;
			attData.mimeType = att.type;
			attData.type = attConst.type.ATT;
			attDataList.push(attData);
		}

		return this.withAttachmentLocks(c, attDataList.map(item => item.key), async () => {
			await orm(c).insert(att).values(attDataList).run();

			for (let att of attList) {
				await r2Service.putObj(c, att.key, att.buff, {
					contentType: att.type,
					contentDisposition: `attachment;filename=${att.filename}`
				});
			}
		});

	},

	async saveArticleAtt(c, attDataList, userId, accountId, emailId) {
		return this.withAttachmentLocks(c, attDataList.map(item => item.key), async () => {
			for (let attData of attDataList) {
				attData.userId = userId;
				attData.emailId = emailId;
				attData.accountId = accountId;
				attData.type = attConst.type.EMBED;
				if (!attData.buff) {
					continue;
				}
				await r2Service.putObj(c, attData.key, attData.buff, {
					contentType: attData.mimeType,
					cacheControl: `max-age=259200`,
					contentDisposition: `inline;filename=${attData.filename}`
				});
				delete attData.buff;
			}

			await orm(c).insert(att).values(attDataList).run();
		});

	},

	async removeByUserIds(c, userIds) {
		await this.removeAttByField(c, 'user_id', userIds);
	},

	async removeByEmailIds(c, emailIds) {
		await this.removeAttByField(c, 'email_id', emailIds);
	},

	selectByEmailIds(c, emailIds) {
		return orm(c).select().from(att).where(
			and(
				inArray(att.emailId, emailIds),
				eq(att.type, attConst.type.ATT)
			))
			.all();
	},

	async removeAttByField(c, fieldName, fieldValues) {
		if (!['user_id', 'email_id', 'account_id'].includes(fieldName)) throw new Error('Invalid attachment field');
		if (!Array.isArray(fieldValues) || fieldValues.length === 0) return;
		const statements = [];
		for (const value of new Set(fieldValues)) {
			// Old objects do not record their storage origin. Queue them as
			// unresolved rather than deleting a shared file or guessing a bucket.
			// The queue and reference removal are committed together.
			statements.push(c.env.db.prepare(`INSERT OR IGNORE INTO account_deletion_object_queue
				(user_id, storage_type, object_key)
				SELECT 0, 'UNRESOLVED', key FROM attachments WHERE ${fieldName} = ?`).bind(value));
			statements.push(c.env.db.prepare(`DELETE FROM attachments WHERE ${fieldName} = ?`).bind(value));
		}
		await c.env.db.batch(statements);
	},

	async removeByAccountId(c, accountId) {
		await this.removeAttByField(c, "account_id", [accountId])
	},

	selectOneByKeys(c, keys) {
		if (!keys || keys.length === 0) {
			return []
		}
		return orm(c).select().from(att).where(inArray(att.key, keys)).orderBy(desc(att.attId)).groupBy(att.key).all();
	}
};

export default attService;

import multer from 'multer';
import { Request } from 'express';
import { AppError } from '../utils/app-error';
import { HttpStatus } from '../config/http-status.config';
import { cloudinary } from '../config/cloudinary-config';

const DEFAULT_ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp'];

const MAGIC_NUMBERS: Record<string, number[]> = {
  'image/jpeg': [0xff, 0xd8, 0xff],
  'image/png': [0x89, 0x50, 0x4e, 0x47],
  'image/webp': [0x52, 0x49, 0x46, 0x46],
};

const validateMagicNumber = (buffer: Buffer, mimetype: string): boolean => {
  const signature = MAGIC_NUMBERS[mimetype];
  if (!signature) return false;

  for (let i = 0; i < signature.length; i++) {
    if (buffer[i] !== signature[i]) return false;
  }

  if (mimetype === 'image/webp') {
    const webpSignature = [0x57, 0x45, 0x42, 0x50];
    for (let i = 0; i < webpSignature.length; i++) {
      if (buffer[8 + i] !== webpSignature[i]) return false;
    }
  }

  return true;
};

const createFileFilter = (allowedMimeTypes: string[]) => {
  return (
    _req: Request,
    file: Express.Multer.File,
    cb: multer.FileFilterCallback
  ) => {
    if (!allowedMimeTypes.includes(file.mimetype)) {
      return cb(
        new AppError(
          'Invalid file type. Only JPEG, PNG, and WebP allowed.',
          HttpStatus.BAD_REQUEST
        )
      );
    }
    cb(null, true);
  };
};

interface UploadOptions {
  field: string;
  folder: string;
  maxSize?: number;
  allowedMimeTypes?: string[];
  transformations?: object[];
  skipMagicValidation?: boolean;
}

export const createUploadMiddleware = (options: UploadOptions) => {
  const {
    field,
    folder,
    maxSize = 3 * 1024 * 1024,
    allowedMimeTypes = DEFAULT_ALLOWED_MIME_TYPES,
    transformations = [
      { width: 500, height: 500, crop: 'limit' },
      { quality: 'auto:good' },
      { fetch_format: 'auto' },
    ],
    skipMagicValidation = false,
  } = options;

  const upload = multer({
    storage: multer.memoryStorage(),
    fileFilter: createFileFilter(allowedMimeTypes),
    limits: {
      fileSize: maxSize,
      files: 1,
    },
  }).single(field);

  const validateAndUpload = async (
    req: Request,
    _res: unknown,
    next: (err?: Error) => void
  ) => {
    if (!req.file) return next();

    try {
      const buffer = req.file.buffer;

      if (
        !skipMagicValidation &&
        !validateMagicNumber(buffer, req.file.mimetype)
      ) {
        throw new AppError(
          "Invalid file content. File doesn't match it claimed type'",
          HttpStatus.BAD_REQUEST
        );
      }

      const uniqueId = `${Date.now()}-${Math.random().toString(36).substring(2, 10)}`;

      const allowedFormats = allowedMimeTypes.map((type) => type.split('/')[1]);

      const uploadResult = await new Promise<{
        secure_url: string;
        public_id: string;
        bytes: number;
        format: string;
      }>((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
          {
            folder,
            public_id: uniqueId,
            allowed_formats: allowedFormats,
            transformation: transformations,
            resource_type: 'image',
          },
          (error, result) => {
            if (error) {
              reject(error);
            } else if (result) {
              resolve(result);
            } else {
              reject(new Error('Upload failed: No result returned'));
            }
          }
        );

        uploadStream.end(buffer);
      });

      req.file.path = uploadResult.secure_url;
      req.file.filename = uploadResult.public_id;

      (req.file as any).cloudinary = {
        publicId: uploadResult.public_id,
        url: uploadResult.secure_url,
        bytes: uploadResult.bytes,
        format: uploadResult.format,
      };

      next();
    } catch (error) {
      if (error instanceof AppError) {
        next(error);
      } else {
        next(
          new AppError('File upload failed.', HttpStatus.INTERNAL_SERVER_ERROR)
        );
      }
    }
  };

  return [upload, validateAndUpload];
};

export const avatarUpload = createUploadMiddleware({
  field: 'avatar',
  folder: 'avatars',
  maxSize: 3 * 1024 * 1024,
});

export const deleteFromCloudinary = async (
  publicId: string
): Promise<boolean> => {
  if (!publicId) {
    console.warn('[Cloudinary] cannot delete: publicId is empty');
    return false;
  }

  try {
    const result = await cloudinary.uploader.destroy(publicId);

    return result.result === 'ok' || result.result === 'not found';
  } catch {
    return false;
  }
};
